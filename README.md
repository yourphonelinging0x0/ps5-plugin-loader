# ploader

Unstable, work-in-progress PRX injector. 

**Status:** Highly unstable. In development. I might update this occasionally, but no promises.

## Compatibility
* **Firmware:** Tested on **12.20 ONLY**. I have no idea how this behaves on other firmwares.
* **Games:** Tested on **PS4 games running in backward compatibility mode on PS5**. It apparently works. Native PS5 games are untested.

## Usage
1. Place your `.prx` files on the console.
2. Configure `/data/plugins/ploader.ini` correctly.
3. **Boot the game first.**
4. Send the `payload.elf`.

You must re-send the payload every time you restart the game. I opted for this manual trigger method instead of writing an infinite polling background loop. 

## Future Updates
I will likely only push stability fixes to this repo once I figure out how to hook `SceShell` to build a better, automatic injection system. Until then, use it as-is.

## INI Format
```ini
[CUSA12345] ; Title ID
/data/plugins/my_plugin.prx = true
