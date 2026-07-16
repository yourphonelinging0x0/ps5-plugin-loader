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
#define MAX_PLUGINS       32
#define MAX_TITLES        128
#define MAX_PATH_LEN      255
#define MAX_TITLE_ID_LEN  16

#define NID_LOADMOD       "wzvqT4UqKX8" // sceKernelLoadStartModule
#define NID_SYSCALL       "HoLVWNanBBc" // getpid

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

#define AUTHID_SYSTEM     0x4801000000000013ULL
#define AUTHID_DEBUGGER   0x4800000000010003ULL

#define SHELLCODE_FN_OFFSET 14

/* 
we preserve the first argument (RDI) and zero out the others (RSI, RDX, RCX, R8, R9).
calls the patched function pointer at offset 14 (mov r15, imm64).
it ends with INT3 (0xCC) to generate a SIGTRAP and return control to ptrace (as i saw etahen doing).
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

typedef struct {
	uint32_t app_id;
	uint64_t unknown1;
	char     title_id[16];
	char     unknown2[0x40];
} app_info_t;

int sceKernelSendNotificationRequest(int, void*, size_t, int);
int sceKernelGetAppInfo(pid_t, app_info_t*);

typedef struct {
	char title_id[MAX_TITLE_ID_LEN + 1];
	char paths[MAX_PLUGINS][MAX_PATH_LEN + 1];
	int  path_count;
} plugin_entry_t;

static plugin_entry_t g_plugins[MAX_TITLES];
static int            g_plugin_count = 0;

static void log_print(const char* fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	klog_printf("[ploader] %s\n", buf);
}

static void log_notify(const char* fmt, ...)
{
	char msg[200];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	struct { char unused[45]; char message[3075]; } req;
	memset(&req, 0, sizeof(req));
	snprintf(req.message, sizeof(req.message), "[ploader] %s", msg);
	sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
	log_print("%s", msg);
}

////////// PTRACE STUFF //////////

// remembering that you can find the same thing in https://github.com/ps5-payload-dev/elfldr/blob/master/pt.c
// i just made some adjustments and wanted to make the implementation clear here

static int sys_ptrace(int request, pid_t pid, caddr_t addr, int data)
{
	pid_t    mypid = getpid();
	uint64_t authid = kernel_get_ucred_authid(mypid);

	if (!authid) {
		log_print("sys_ptrace: authid=0");
		return -1;
	}

	kernel_set_ucred_authid(mypid, AUTHID_DEBUGGER);
	int ret = (int)syscall(SYS_ptrace, request, pid, addr, data);
	int err = errno;
	kernel_set_ucred_authid(mypid, authid);

	if (ret == -1 && err != ESRCH) {
		log_print("sys_ptrace: req=%d errno=%d", request, err);
	}
	
	errno = err;
	return ret;
}

static int waitpid_timeout(pid_t pid, int* status, int timeout_ms)
{
	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);
	
	while (true) {
		pid_t res = waitpid(pid, status, WNOHANG);
		if (res == pid) return 1;
		if (res < 0) return -1;
		
		clock_gettime(CLOCK_MONOTONIC, &now);
		long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
		if (elapsed_ms >= timeout_ms) return 0;
		
		usleep(10000); // 10ms
	}
}

static int pt_attach(pid_t pid)
{
	int retries = 5;
	while (retries-- > 0) {
		if (sys_ptrace(PT_ATTACH, pid, 0, 0) == 0) {
			int status = 0;
			if (waitpid_timeout(pid, &status, 2000) > 0) {
				log_print("pt_attach: pid=%d status=0x%x sig=%d", (int)pid, status, WSTOPSIG(status));
				return 0;
			}
			sys_ptrace(PT_DETACH, pid, 0, 0);
		}
		
		if (errno == ESRCH) {
			log_print("pt_attach: pid %d died or not ready, retrying...", (int)pid);
			usleep(500000); // 500ms
			continue;
		}
		break; 
	}
	return -1;
}

static int pt_detach(pid_t pid)
{
	return sys_ptrace(PT_DETACH, pid, 0, 0);
}

static int pt_getregs(pid_t pid, struct reg* r)
{
	return sys_ptrace(PT_GETREGS, pid, (caddr_t)r, 0);
}

static int pt_setregs(pid_t pid, const struct reg* r)
{
	return sys_ptrace(PT_SETREGS, pid, (caddr_t)r, 0);
}

static int pt_copyin(pid_t pid, const void* buf, intptr_t addr, size_t len)
{
	struct ptrace_io_desc iod = {
		.piod_op = PIOD_WRITE_D,
		.piod_offs = (void*)addr,
		.piod_addr = (void*)buf,
		.piod_len = len
	};
	return sys_ptrace(PT_IO, pid, (caddr_t)&iod, 0);
}

static intptr_t pt_resolve(pid_t pid, const char* nid)
{
	intptr_t a = kernel_dynlib_resolve(pid, 0x1, nid);
	if (a) 
		return a;
	return kernel_dynlib_resolve(pid, 0x2001, nid);
}

static long pt_syscall(pid_t pid, int sysno, ...)
{
	intptr_t addr = pt_resolve(pid, NID_SYSCALL);
	if (!addr) {
		log_print("pt_syscall: failed to resolve syscall wrapper");
		return -1;
	}
	addr += 0xA; 
	// the NID resolves to a wrapper function in libkernel, the actual syscall instruction or the correct entry point for hijacking is located at offset 0xA within this wrapper in fw 12.20
    //(i cant say if this offset changes depending on the fw, i only tested it on the previously mentioned firmware)

	struct reg jmp, bak;
	if (pt_getregs(pid, &bak)) return -1;
	memcpy(&jmp, &bak, sizeof(jmp));

	jmp.r_rip = addr;
	jmp.r_rax = (uint64_t)sysno;

	va_list ap;
	va_start(ap, sysno);
	jmp.r_rdi = va_arg(ap, uint64_t);
	jmp.r_rsi = va_arg(ap, uint64_t);
	jmp.r_rdx = va_arg(ap, uint64_t);
	jmp.r_r10 = va_arg(ap, uint64_t);
	jmp.r_r8 = va_arg(ap, uint64_t);
	jmp.r_r9 = va_arg(ap, uint64_t);
	va_end(ap);

	if (pt_setregs(pid, &jmp)) return -1;

	int max_steps = 10000;
	while (jmp.r_rsp <= bak.r_rsp && max_steps-- > 0) {
		if (sys_ptrace(PT_STEP, pid, (caddr_t)1, 0)) return -1;
		if (waitpid_timeout(pid, NULL, 1000) <= 0) return -1;
		if (pt_getregs(pid, &jmp)) return -1;
	}

	if (max_steps <= 0) {
		log_print("pt_syscall: timeout! rsp did not return.");
		pt_setregs(pid, &bak);
		return -1;
	}

	pt_setregs(pid, &bak);
	return (long)jmp.r_rax;
}

static intptr_t pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags, int fd, off_t off)
{
	return pt_syscall(pid, SYS_mmap, (uint64_t)addr, (uint64_t)len, (uint64_t)prot, (uint64_t)flags, (uint64_t)fd, (uint64_t)off);
}

static int pt_munmap(pid_t pid, intptr_t addr, size_t len)
{
	return (int)pt_syscall(pid, SYS_munmap, (uint64_t)addr, (uint64_t)len);
}

static long pt_call_continue(pid_t pid, intptr_t addr, ...)
{
	struct reg jmp, bak;
	if (pt_getregs(pid, &bak)) return -1;
	memcpy(&jmp, &bak, sizeof(jmp));

	jmp.r_rip = addr;

	va_list ap;
	va_start(ap, addr);
	jmp.r_rdi = va_arg(ap, uint64_t);
	jmp.r_rsi = va_arg(ap, uint64_t);
	jmp.r_rdx = va_arg(ap, uint64_t);
	jmp.r_rcx = va_arg(ap, uint64_t);
	jmp.r_r8 = va_arg(ap, uint64_t);
	jmp.r_r9 = va_arg(ap, uint64_t);
	va_end(ap);

	if (pt_setregs(pid, &jmp)) return -1;

	int status = 0;
	sys_ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
	
	if (waitpid_timeout(pid, &status, 5000) <= 0) {
		log_print("pt_call_continue: waitpid timeout or error");
		pt_setregs(pid, &bak);
		return -1;
	}

	int sig = WIFSTOPPED(status) ? WSTOPSIG(status) : -1;
	log_print("pt_call_continue: stop status=0x%x sig=%d", status, sig);

	if (!WIFSTOPPED(status) || sig != SIGTRAP)
		log_print("pt_call_continue: expected SIGTRAP(5), got sig=%d", sig);

	if (pt_getregs(pid, &jmp)) return -1;

	log_print("pt_call_continue: RIP=0x%llx RAX=0x%llx", (unsigned long long)jmp.r_rip, (unsigned long long)jmp.r_rax);

	pt_setregs(pid, &bak);
	return (long)jmp.r_rax;
}

////////// PROCESS //////////

// it allows us to gain root access within the target process and enables it to see the entire '/' directory
// which is necessary to load the plugins from /data/plugins/
static int jb_pid(pid_t pid)
{
	intptr_t rv = kernel_get_root_vnode();
	intptr_t ucred = kernel_get_proc_ucred(pid);
	intptr_t fd = kernel_get_proc_filedesc(pid);

	log_print("jb_pid: pid=%d rv=0x%llx ucred=0x%llx fd=0x%llx", (int)pid, (unsigned long long)rv, (unsigned long long)ucred, (unsigned long long)fd);

	if (!rv || !ucred || !fd) {
		log_print("jb_pid: missing kernel pointers");
		return -1;
	}

	const uint32_t zero = 0;
	const int64_t caps = -1LL;
	const uint64_t authid = AUTHID_SYSTEM;
	const uint8_t attr = 0x80;

	// you can use goto
	#define TRY_COPYIN(src, dst, len) \
		do { if (kernel_copyin(src, dst, len) < 0) { log_print("jb_pid: copyin failed at line %d", __LINE__); return -1; } } while(0) // __LINE__ return the current source code line number

	TRY_COPYIN(&zero, ucred + UCRED_UID, 4);
	TRY_COPYIN(&zero, ucred + UCRED_RUID, 4);
	TRY_COPYIN(&zero, ucred + UCRED_SVUID, 4);
	TRY_COPYIN(&zero, ucred + UCRED_NGROUPS, 4);
	TRY_COPYIN(&zero, ucred + UCRED_RGID, 4);
	TRY_COPYIN(&zero, ucred + UCRED_SVGID, 4);
	TRY_COPYIN(&authid, ucred + UCRED_AUTHID, 8);
	TRY_COPYIN(&caps, ucred + UCRED_CAPS0, 8);
	TRY_COPYIN(&caps, ucred + UCRED_CAPS1, 8);
	TRY_COPYIN(&attr, ucred + UCRED_ATTR0, 1);

	#undef TRY_COPYIN

	kernel_set_proc_rootdir(pid, rv);
	kernel_set_proc_jaildir(pid, rv);

	log_print("jb_pid: verify authid=0x%llx", (unsigned long long)kernel_get_ucred_authid(pid));
	return 0;
}

// function to find the pid of an active process by its title
static pid_t find_pid_by_title(const char* title_id)
{
	int mib[4] = { 1, 14, 8, 0 }; // CTL_KERN, KERN_PROC, KERN_PROC_ALL
	size_t sz = 0;
	sysctl(mib, 4, NULL, &sz, NULL, 0);

	uint8_t* buf = malloc(sz);
	if (!buf) {
		log_print("find_pid_by_title: malloc failed");
		return -1;
	}
	
	if (sysctl(mib, 4, buf, &sz, NULL, 0) < 0) {
		log_print("find_pid_by_title: sysctl failed");
		free(buf);
		return -1;
	}

	pid_t self = getpid();
	pid_t found = -1;
	uint8_t* p = buf;

	while (p + 4 <= buf + sz) {
		int elen = *(int*)p;
		if (elen <= 0 || p + elen > buf + sz) break;

		pid_t pid = *(pid_t*)(p + 72);
		if (pid > 1 && pid != self) {
			app_info_t info;
			memset(&info, 0, sizeof(info));
			if (sceKernelGetAppInfo(pid, &info) == 0 && info.title_id[0]) {
				log_print("find_pid_by_title: pid=%d title=[%s]", (int)pid, info.title_id);
				if (strncmp(info.title_id, title_id, MAX_TITLE_ID_LEN) == 0) {
					found = pid;
					break;
				}
			}
		}
		p += elen;
	}

	free(buf);
	log_print("find_pid_by_title: [%s] -> pid=%d", title_id, (int)found);
	return found;
}

// function responsible for parsing and interpreting the configured .ini file
static void load_ini(const char* ini_path)
{
	FILE* f = fopen(ini_path, "r");
	if (!f) {
		log_print("load_ini: file not found: %s", ini_path);
		return;
	}

	char line[1024];
	char current_tid[MAX_TITLE_ID_LEN + 1] = { 0 };

	while (fgets(line, sizeof(line), f)) {
		char* s = line;

		while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
		size_t len = strlen(s);
		if (len == 0) continue;

		char* end = s + len - 1;
		while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) {
			*end-- = '\0';
			len--;
		}

		if (s[0] == '\0' || s[0] == ';' || s[0] == '#') continue;

		if (s[0] == '[' && end[0] == ']') {
			end[0] = '\0';
			const char* tid = s + 1;
			if (strlen(tid) > MAX_TITLE_ID_LEN) {
				log_print("load_ini: title_id too long: %s", tid);
				current_tid[0] = '\0';
				continue;
			}
			snprintf(current_tid, sizeof(current_tid), "%s", tid);
			log_print("load_ini: section [%s]", current_tid);
			continue;
		}

		if (current_tid[0] == '\0') continue;

		char* eq = strchr(s, '=');
		if (!eq) continue;
		*eq = '\0';

		char* path = s;
		char* value = eq + 1;
		
		while (*path == ' ' || *path == '\t') path++;
		while (*value == ' ' || *value == '\t') value++;

		if (strcmp(value, "true") != 0) continue;

		size_t path_len = strlen(path);
		if (path_len == 0 || path_len > MAX_PATH_LEN) {
			log_print("load_ini: invalid path length (%zu): %s", path_len, path);
			continue;
		}
		if (strstr(path, "..") != NULL) {
			log_print("load_ini: directory traversal detected in: %s", path);
			continue;
		}

		int slot = -1;
		for (int i = 0; i < g_plugin_count; i++) {
			if (strcmp(g_plugins[i].title_id, current_tid) == 0) {
				slot = i;
				break;
			}
		}

		if (slot < 0 && g_plugin_count < MAX_TITLES) {
			slot = g_plugin_count++;
			snprintf(g_plugins[slot].title_id, sizeof(g_plugins[slot].title_id), "%s", current_tid);
			g_plugins[slot].path_count = 0;
		}

		if (slot >= 0 && g_plugins[slot].path_count < MAX_PLUGINS) {
			char* dst = g_plugins[slot].paths[g_plugins[slot].path_count++];
			snprintf(dst, sizeof(g_plugins[slot].paths[0]), "%s", path);
			log_print("load_ini: [%s] += %s", current_tid, dst);
		} else if (slot >= 0) {
			log_print("load_ini: max plugins reached for [%s]", current_tid);
		}
	}

	fclose(f);
	log_print("load_ini: %d title(s) loaded", g_plugin_count);
}

static long inject_prx_attached(pid_t pid, const char* prx_path)
{
	log_print("inject_prx_attached: START pid=%d path=[%s]", (int)pid, prx_path);

	if (access(prx_path, R_OK) != 0) {
		log_print("inject_prx_attached: file not found or not readable: %s", prx_path);
		return -1;
	}

	const intptr_t fn = pt_resolve(pid, NID_LOADMOD);
	if (!fn) {
		log_print("inject_prx_attached: NID_LOADMOD not resolved");
		return -1;
	}
	log_print("inject_prx_attached: sceKernelLoadStartModule @ 0x%lx", (unsigned long)fn);

	const size_t path_len = strlen(prx_path) + 1;

	// we do NOT write the shellcode to the game eboot.bin!
    // instead, allocate a temporary, anonymous (rw) memory page in the target process's address space using 'mmap'
	const intptr_t rw_page = pt_mmap(pid, 0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (rw_page == (intptr_t)-1 || rw_page == 0) {
		log_print("inject_prx_attached: pt_mmap failed errno=%d", errno);
		return -1;
	}
	log_print("inject_prx_attached: rw_page=0x%lx", (unsigned long)rw_page);

	const intptr_t remote_path = rw_page;
	const intptr_t remote_sc = rw_page + 0x1000;
	long mod = -1;

	do {
		if (pt_copyin(pid, prx_path, remote_path, path_len) < 0) {
			log_print("inject_prx_attached: copyin path failed");
			break;
		}

		uint8_t sc[sizeof(k_shellcode)];
		memcpy(sc, k_shellcode, sizeof(sc));
		memcpy(sc + SHELLCODE_FN_OFFSET, &fn, sizeof(fn));

		if (pt_copyin(pid, sc, remote_sc, sizeof(sc)) < 0) {
			log_print("inject_prx_attached: copyin shellcode failed");
			break;
		}

		int mp = kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);
		log_print("inject_prx_attached: kernel_mprotect RWX ret=%d", mp);

		if (mp != 0) {
			log_print("inject_prx_attached: kernel_mprotect failed");
			break;
		}

		log_print("inject_prx_attached: executing shellcode...");
		mod = pt_call_continue(pid, remote_sc, (uint64_t)remote_path, 0ULL, 0ULL, 0ULL, 0ULL, 0ULL);

		log_print("inject_prx_attached: RAX=0x%llx  modid=%d", (unsigned long long)(uint64_t)mod, (int32_t)mod);

		kernel_mprotect(pid, remote_sc, 0x1000, PROT_READ | PROT_WRITE);
	} while (0);

	pt_munmap(pid, rw_page, 0x4000);

	log_print("inject_prx_attached: END");
	return mod;
}

static void inject_all(void)
{
	for (int i = 0; i < g_plugin_count; i++) {
		const char* tid = g_plugins[i].title_id;
		log_print("inject_all: searching for [%s]", tid);
		pid_t pid = find_pid_by_title(tid);

		if (pid < 0) {
			log_notify("ploader: [%s] not running, skipping", tid);
			continue;
		}

		log_notify("ploader: [%s] pid=%d -> injecting %d plugin(s)...", tid, (int)pid, g_plugins[i].path_count);

		if (pt_attach(pid) < 0) {
			log_notify("ploader: [%s] failed to attach", tid);
			continue;
		}

		if (jb_pid(pid) != 0) {
			log_print("inject_all: jb_pid failed");
			pt_detach(pid);
			continue;
		}

		for (int p = 0; p < g_plugins[i].path_count; p++) {
			const char* path = g_plugins[i].paths[p];
			const long ret = inject_prx_attached(pid, path);
			const int32_t rc = (int32_t)ret;

			if (rc > 0)
				log_notify("ploader: [%s] OK modid=%d  %s", tid, rc, path);
			else if (rc == 0)
				log_notify("ploader: [%s] modid=0 (already loaded?)  %s", tid, path); // sometimes a false positive occurs after load, restarting the game, and loading again.
			else
				log_notify("ploader: [%s] FAILED 0x%08x  %s", tid, (uint32_t)rc, path);
		}

		pt_detach(pid);
	}
}

int main(void)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = SIG_DFL;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);

	payload_args_t* args = payload_get_args();
	if (args)
		log_print("main: kbase=0x%llx", (unsigned long long)args->kdata_base_addr);
	else
		log_print("main: payload_get_args=NULL");

	log_print("main: pid=%d fw=0x%x", (int)getpid(), kernel_get_fw_version());

	load_ini(DEFAULT_INI_PATH);

	if (g_plugin_count == 0) {
		log_notify("ploader: no plugins in .ini done");
		return 0;
	}

	log_notify("ploader: %d title(s) configured", g_plugin_count);

	inject_all();

	log_notify("end.");
	return 0;
}