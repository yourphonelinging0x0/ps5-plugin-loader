#include <ps5/klog.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stddef.h>
#include <sys/sysctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <machine/reg.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>

////////// SOME DEFINITIONS //////////

#define DEFAULT_INI_PATH  "/data/plugins/ploader.ini"
#define MAX_PLUGINS       10  // you can change here if you want more plugins.
#define MAX_TITLES        10  // also increase this here if you want to configure it for more processes.
#define MAX_PATH_LEN      255
#define MAX_TITLE_ID_LEN  16

#define NID_LOADSTARTMODULE   "wzvqT4UqKX8" // sceKernelLoadStartModule
#define NID_GETPID        "HoLVWNanBBc" // getpid

#define UCRED_UID         0x04
#define UCRED_RUID        0x08
#define UCRED_SVUID       0x0C
#define UCRED_NGROUPS     0x10
#define UCRED_RGID        0x14
#define UCRED_SVGID       0x18
#define UCRED_AUTHID      0x58
#define UCRED_CAPS0       0x60
#define UCRED_CAPS1       0x68
#define UCRED_ATTR0       0x83

#define AUTHID_SYSTEM     0x4801000000000013ULL // unsigned long long
#define AUTHID_DEBUGGER   0x4800000000010003ULL // unsigned long long

#define SHELLCODE_FN_OFFSET 14

////////// SHELLCODE //////////

/*
we preserve the first argument (RDI) and zero out the others (RSI, RDX, RCX, R8, R9).
calls the patched function pointer at offset 14 (mov r15, imm64).
it ends with INT3 (0xCC) to generate a SIGTRAP and return control to ptrace (as i saw etaHEN doing).
*/
static const uint8_t k_shellcode[] = {
	0x55,                               // push rbp
	0x48, 0x89, 0xE5,                   // mov  rbp, rsp
	0x48, 0x83, 0xE4, 0xF0,             // and  rsp, -16   (16-byte ABI alignment)
	0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 0x28  (scratch space)
	0x49, 0xBF,                         // mov  r15, imm64 <- fn patched at runtime
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x31, 0xF6,                         // xor  esi, esi   (arg2 = 0)
	0x31, 0xD2,                         // xor  edx, edx   (arg3 = 0)
	0x31, 0xC9,                         // xor  ecx, ecx   (arg4 = 0)
	0x45, 0x31, 0xC0,                   // xor  r8d, r8d   (arg5 = 0)
	0x45, 0x31, 0xC9,                   // xor  r9d, r9d   (arg6 = 0)
	0x41, 0xFF, 0xD7,                   // call r15        (rdi = path, already set)
	0x48, 0x89, 0xEC,                   // mov  rsp, rbp
	0x5D,                               // pop  rbp
	0xCC                                // int3  <- tracer wakes here, RAX = result
};

////////// SONY THINGS //////////

// types
typedef struct {
	uint32_t app_id;
	uint64_t unknown1;
	char     title_id[16];
	char     unknown2[0x40];
} app_info_t;

typedef struct {
	char title_id[MAX_TITLE_ID_LEN + 1];
	char paths[MAX_PLUGINS][MAX_PATH_LEN + 1];
	int  path_count;
} plugin_entry_t;

// imports
int sceKernelSendNotificationRequest(int, void*, size_t, int);
int sceKernelGetAppInfo(pid_t, app_info_t*);

//
static plugin_entry_t g_plugins[MAX_TITLES];
static int            g_plugin_count = 0;

////////// LOGGING //////////

static void log(const char* fmt, ...) {
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	klog_printf("[ploader] %s\n", buf);
}

static void notify(const char* fmt, ...) {
	char msg[256];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	struct {
		char unused[45];
		char message[3075];
	} req = { 0 };
	snprintf(req.message, sizeof(req.message), "[ploader] %s", msg);
	sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
	log("%s", msg);
}

////////// PTRACE //////////

// from github.com/ps5-payload-dev/elfldr/blob/master/pt.c
static int sys_ptrace(int req, pid_t pid, caddr_t addr, int data) {
	pid_t mypid = getpid();
	uint64_t authid = kernel_get_ucred_authid(mypid);
	if (!authid)
		return -1;

	kernel_set_ucred_authid(mypid, AUTHID_DEBUGGER);
	int ret = syscall(SYS_ptrace, req, pid, addr, data);
	int err = errno;
	kernel_set_ucred_authid(mypid, authid);
	errno = err;
	return ret;
}

static int waitpid_timeout(pid_t pid, int* status, int ms) {
	for (int i = 0; i < ms / 10; i++) {
		pid_t res = waitpid(pid, status, WNOHANG);
		if (res == pid)
			return 1;

		if (res < 0)
			return -1;

		usleep(10000);
	}
	return 0;
}

static int pt_attach(pid_t pid) {
	for (int i = 0; i < 5; i++) {
		if (sys_ptrace(PT_ATTACH, pid, 0, 0) == 0 && waitpid_timeout(pid, NULL, 2000) > 0)
			return 0;

		if (errno == ESRCH)
			usleep(500000);
		else
			break;
	}
	return -1;
}

static int pt_detach(pid_t pid) {
	return sys_ptrace(PT_DETACH, pid, 0, 0);
}

static int pt_getregs(pid_t pid, struct reg* r) {
	return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}

static int pt_setregs(pid_t pid, const struct reg* r) {
	return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}

static int pt_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len) {
	struct ptrace_io_desc iod = {
		.piod_op = PIOD_WRITE_D,
		.piod_offs = (void*)addr,
		.piod_addr = (void*)buf,
		.piod_len = len
	};

	return sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}

static intptr_t pt_resolve(pid_t pid, const char* nid) {
	intptr_t a = kernel_dynlib_resolve(pid, 0x1, nid);
	return a ? a : kernel_dynlib_resolve(pid, 0x2001, nid);
}

static long pt_syscall(pid_t pid, int sysno, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
	intptr_t addr = pt_resolve(pid, NID_GETPID);
	if (!addr)
		return -1;
	addr += 0xA; // skip wrapper prologue to call syscall instruction directly

	struct reg jmp, bak;
	if (pt_getregs(pid, &bak))
		return -1;

	jmp = bak;
	jmp.r_rip = addr;
	jmp.r_rax = sysno;
	jmp.r_rdi = a1; jmp.r_rsi = a2; jmp.r_rdx = a3;
	jmp.r_r10 = a4; jmp.r_r8 = a5;  jmp.r_r9 = a6;

	if (pt_setregs(pid, &jmp))
		return -1;

	for (int i = 0; i < 10000; i++) {
		if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0) || waitpid_timeout(pid, NULL, 1000) <= 0)
			return -1;

		if (pt_getregs(pid, &jmp))
			return -1;

		if (jmp.r_rsp > bak.r_rsp)
			break;
	}

	pt_setregs(pid, &bak);
	return jmp.r_rax;
}

static intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags, int fd, off_t off) {
	return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}

static int pt_munmap(pid_t pid, intptr_t addr, size_t len) {
	return pt_syscall(pid, SYS_munmap, addr, len, 0, 0, 0, 0);
}

static long pt_call(pid_t pid, intptr_t addr, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
	struct reg jmp, bak;
	if (pt_getregs(pid, &bak))
		return -1;

	jmp = bak;
	jmp.r_rip = addr; // address
	jmp.r_rdi = a1;   // arg1
	jmp.r_rsi = a2;   // arg2
	jmp.r_rdx = a3;   // arg3
	jmp.r_rcx = a4;   // arg4
	jmp.r_r8 = a5;    // arg5
	jmp.r_r9 = a6;    // arg6

	if (pt_setregs(pid, &jmp))
		return -1;

	sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);

	int status = 0;
	if (waitpid_timeout(pid, &status, 5000) <= 0 || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		pt_setregs(pid, &bak);
		return -1;
	}

	if (pt_getregs(pid, &jmp))
		return -1;

	pt_setregs(pid, &bak);
	return jmp.r_rax;
}

////////// PROCESS //////////

// necessary for the loader to be able to see everything starting from '/'
static int jb_pid(pid_t pid) {
    intptr_t rv = kernel_get_root_vnode();
    intptr_t ucred = kernel_get_proc_ucred(pid);

    if (!rv || !ucred)
        return -1;

    uint32_t zero = 0;
    int64_t caps = -1LL; // long long
    uint64_t authid = AUTHID_SYSTEM;
    uint8_t attr = 0x80;

    if (kernel_copyin(&zero, ucred + UCRED_UID, 4) < 0)
        return -1;

    if (kernel_copyin(&zero, ucred + UCRED_RUID, 4) < 0)
        return -1;

    if (kernel_copyin(&zero, ucred + UCRED_SVUID, 4) < 0)
        return -1;

    if (kernel_copyin(&zero, ucred + UCRED_NGROUPS, 4) < 0)
        return -1;

    if (kernel_copyin(&zero, ucred + UCRED_RGID, 4) < 0)
        return -1;

    if (kernel_copyin(&zero, ucred + UCRED_SVGID, 4) < 0)
        return -1;

    if (kernel_copyin(&authid, ucred + UCRED_AUTHID, 8) < 0)
        return -1;

    if (kernel_copyin(&caps, ucred + UCRED_CAPS0, 8) < 0)
        return -1;

    if (kernel_copyin(&caps, ucred + UCRED_CAPS1, 8) < 0)
        return -1;

    if (kernel_copyin(&attr, ucred + UCRED_ATTR0, 1) < 0)
        return -1;

    kernel_set_proc_rootdir(pid, rv);
    kernel_set_proc_jaildir(pid, rv);

    return 0;
}

static pid_t find_pid(const char* title_id) {
	int mib[4] = { 1, 14, 8, 0 }; // if you use 'CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0' directly, it won't find the process.
	size_t sz = 0;
	sysctl(mib, 4, NULL, &sz, NULL, 0);
	uint8_t* buf = malloc(sz);
	if (!buf || sysctl(mib, 4, buf, &sz, NULL, 0) < 0) {
		free(buf);
		return -1;
	}

	pid_t self = getpid(), found = -1;

	for (uint8_t* p = buf; p + 4 <= buf + sz; p += *(int*)p) {
		int elen = *(int*)p;

		if (elen <= 0 || p + elen > buf + sz)
			break;

		pid_t pid = *(pid_t*)(p + 0x48);
		if (pid > 1 && pid != self) {
			app_info_t info = { 0 };
			if (sceKernelGetAppInfo(pid, &info) == 0 && strncmp(info.title_id, title_id, MAX_TITLE_ID_LEN) == 0) {
				found = pid;
				break;
			}
		}
	}
	free(buf);
	return found;
}

static const char* get_filename(const char* path) {
	const char* name = strrchr(path, '/');
	return name ? name + 1 : path;
}

////////// INI PARSER //////////

// load the .ini config
static void load_ini(const char* path) {
	FILE* f = fopen(path, "r");
	if (!f)
		return;

	char line[1024], tid[MAX_TITLE_ID_LEN + 1] = { 0 };
	while (fgets(line, sizeof(line), f)) {
		char* s = line;
		while (*s == ' ' || *s == '\t')
			s++;
		char* end = s + strlen(s) - 1;
		while (end > s && (*end == ' ' || *end == '\r' || *end == '\n')) *end-- = '\0';

		if (*s == '\0' || *s == ';' || *s == '#')
			continue;

		if (*s == '[' && *end == ']') {
			*end = '\0';
			snprintf(tid, sizeof(tid), "%s", s + 1);
			continue;
		}

		if (!*tid)
			continue;

		char* eq = strchr(s, '=');
		if (!eq || strcmp(eq + 1, "true") != 0)
			continue;

		*eq = '\0';

		char* p = s;
		while (*p == ' ' || *p == '\t')
			p++;

		if (!*p || strlen(p) > MAX_PATH_LEN || strstr(p, ".."))
			continue;

		int slot = -1;
		for (int i = 0; i < g_plugin_count; i++) {
			if (strcmp(g_plugins[i].title_id, tid) == 0) {
				slot = i;
				break;
			}
		}

		if (slot < 0 && g_plugin_count < MAX_TITLES) {
			slot = g_plugin_count++;
			snprintf(g_plugins[slot].title_id, sizeof(g_plugins[slot].title_id), "%s", tid);
			g_plugins[slot].path_count = 0;
		}

		if (slot >= 0 && g_plugins[slot].path_count < MAX_PLUGINS) {
			snprintf(g_plugins[slot].paths[g_plugins[slot].path_count++], MAX_PATH_LEN + 1, "%s", p);
		}
	}
	fclose(f);
}

////////// INJECTION //////////

static int inject_prx(pid_t pid, const char* prx_path) {
	if (access(prx_path, R_OK) != 0)
		return -1;

	intptr_t fn = pt_resolve(pid, NID_LOADSTARTMODULE);
	if (!fn)
		return -1;

	// allocate a temporary anonymous read/write memory page at a kernel-selected address using 'mmap'.
	intptr_t rw_page = pt_mmap(pid, 0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rw_page <= 0)
		return -1;

	intptr_t remote_path = rw_page;
	intptr_t remote_sc = rw_page + 0x1000;
	int mod = -1;

	if (pt_copyin(pid, prx_path, remote_path, strlen(prx_path) + 1) >= 0) {
		uint8_t sc[sizeof(k_shellcode)];
		memcpy(sc, k_shellcode, sizeof(sc));
		memcpy(sc + SHELLCODE_FN_OFFSET, &fn, sizeof(fn));

		if (pt_copyin(pid, sc, remote_sc, sizeof(sc)) >= 0) {
			kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
			mod = pt_call(pid, remote_sc, remote_path, 0, 0, 0, 0, 0);
			kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE);
		}
	}

	pt_munmap(pid, rw_page, 0x4000);
	return mod;
}

static void inject_all(void) {
	for (int i = 0; i < g_plugin_count; i++) {
		const char* tid = g_plugins[i].title_id;
		pid_t pid = find_pid(tid);

		if (pid < 0) {
			notify("[%s] Not running", tid);
			continue;
		}

		if (pt_attach(pid) < 0 || jb_pid(pid) != 0) {
			notify("[%s] Attach failed", tid);
			pt_detach(pid);
			continue;
		}

		notify("[%s] Injecting %d...", tid, g_plugins[i].path_count);
		for (int p = 0; p < g_plugins[i].path_count; p++) {
			const char* path = g_plugins[i].paths[p];
			int rc = inject_prx(pid, path);
			if (rc > 0) notify("[%s] OK: %s", tid, get_filename(path));
			else notify("[%s] FAIL: %s", tid, get_filename(path));
		}
		pt_detach(pid);
	}
}

////////// MAIN //////////

int main(void) {
	signal(SIGSEGV, SIG_DFL);
	signal(SIGBUS, SIG_DFL);

	payload_args_t* args = payload_get_args();
	if (args)
		log("Kernel base: 0x%llx", args->kdata_base_addr);

	load_ini(DEFAULT_INI_PATH);
	if (g_plugin_count == 0) {
		notify("Config empty");
		return 0;
	}

	notify("Injector started");
	inject_all();
	notify("Finished");
	return 0;
}