# HantaMap

Maps a PIC payload into the `.data` section of a loaded system DLL and executes it
from there. The host DLL stays functional.

> PoC quality. Not production-ready. Your problem if it breaks.
>
> Concept by the repo owner. Implementation assisted by AI (Claude).

## What it does

1. Loads user32.dll, backs up its `.data` section
2. Writes payload at the tail end of `.data` (host globals at the front stay intact)
3. Marks payload pages `PAGE_EXECUTE`, installs a VEH to proxy read/write faults
4. Payload runs from user32.dll's address space at full speed

## Why `.data`

Code sections get integrity-checked (hash vs on-disk). Data sections don't -- they're
writable, they're supposed to change at runtime. Nobody signature-scans `.data`.

`PAGE_EXECUTE` on the payload pages is the only anomaly. On HVCI systems it's truly
execute-only (scanners can't even read it). Without HVCI, x64 PTEs can't separate
execute from read so it behaves like `PAGE_EXECUTE_READ`.

## Detection

Two theoretical vectors, both bypassable:

- **`VirtualQuery` on `.data` pages** showing `PAGE_EXECUTE` instead of `PAGE_READWRITE`.
  Bypassable by flipping pages back to `PAGE_READWRITE` (with backup data restored)
  while the payload sleeps, and only marking `PAGE_EXECUTE` during active execution.
  Periodic scanners would have to catch the exact window.

- **Thread start address** via `NtQueryInformationThread` pointing into `.data`.
  Bypassable by using a small trampoline in `.text` as the `CreateThread` start,
  which jumps to the real entry. The reported start address stays in `.text`.

With HVCI + both bypasses, detection requires hypervisor-level introspection. No
mainstream AV/EDR runs these checks today.

## Build

MinGW-w64, x64 only.

```
gcc -O2 -nostdlib -fno-asynchronous-unwind-tables -fno-ident \
    -e payload_entry -Wl,--section-alignment,4096 \
    -Wl,--file-alignment,512 -Wl,-s -Wl,--no-seh \
    -o payload.exe payload.c

gcc -O2 -o mapper.exe mapper.c
```

## Run

```
mapper.exe
```

Both binaries in the same directory.

## License

MIT
