# ploader

An experimental and unstable PRX injector for PS5.

**⚠️ Status:** Work in progress. Highly unstable.

## Compatibility

* **Firmware:** Tested on **12.20 ONLY**. Other firmware versions are untested.
* **Games:** Tested on **PS4 games running in backward compatibility mode on PS5**.
* **Native PS5 games:** Untested.

## Usage

1. Place your `.prx` or `.sprx` files on the console. Both formats are supported.
2. Configure `/data/plugins/ploader.ini` correctly.
3. **Boot the PS4 version of the game first.**
4. **Wait until the game has completely finished loading and you are fully inside the game.**
5. **Do not send the payload while the game is on a loading screen or while the game is still loading.**
6. Send `payload.elf`.

> **Important:** Always wait until the game is fully loaded and interactive before sending the payload.

You must re-send the payload every time you restart the game.

## Configuration

`/data/plugins/ploader.ini`

```ini
[CUSA12345] ; Title ID
/data/plugins/my_plugin.prx = true
```

Replace `CUSA12345` with the game's Title ID and add the PRX or SPRX modules you want to load.

## Building

Ploader is built using the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

You **must** use this specific SDK to compile the payload. Follow the repository's instructions to set up your build environment using WSL or native Linux.

Prebuilt versions are also available in the repository's [Releases](../../releases) section.

## Technical Notes

Ploader currently uses `ptrace` thread hijacking and kernel `ucred` manipulation. It allocates a temporary RWX page inside the game's memory space to execute a shellcode trampoline.

It does **not** patch the `eboot.bin` directly.

## Future Updates

The current implementation uses a manual trigger.

Future work may include stability improvements and an automated injection system using `SceShell`.

## Credits And References

Built using the [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk).

Architecture, plugin handling, and general behavior were heavily inspired by and referenced from:

* [GoldHEN](https://github.com/GoldHEN/GoldHEN)
* [GoldHEN Plugins Repository](https://github.com/GoldHEN/GoldHEN_Plugins_Repository)
* [etaHEN](https://github.com/etaHEN/etaHEN)
* [etaHEN Plugins](https://github.com/etaHEN/etaHEN-Plugins)

## Disclaimer

Use it at your own risk. Compatibility and stability are not guaranteed.
