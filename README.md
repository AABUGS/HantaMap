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

`PAGE_EXECUTE` on the payload pages is the only anomaly. On x64 this is equivalent to
`PAGE_EXECUTE_READ` at the hardware level (PTEs can't separate execute from read).
True execute-only would require custom EPT manipulation at the hypervisor level.

## Detection

The PoC as shipped is detectable. Each vector has a known bypass. Stack them all and
the detection surface approaches zero.

| Vector | What catches you | Bypass |
|--------|-----------------|--------|
| Page protection | `VirtualQuery` / `NtQueryVirtualMemory` sees `PAGE_EXECUTE` on `.data` | Timed page flipping -- `PAGE_READWRITE` with backup data during sleep, `PAGE_EXECUTE` only during active execution |
| `VirtualProtect` hooks | AV/AC hooks `NtProtectVirtualMemory`, logs the flip | Manual syscalls |
| Thread start address | `NtQueryInformationThread` reports start in `.data` | `.text` trampoline as `CreateThread` entry |
| Stack walking | Hooked APIs see return address in `.data` | Stack spoofing + `.text` call trampolines |
| RIP sampling | ETW / kernel profiler samples RIP inside `.data` | Only vulnerable during active execution window -- mostly blocked in kernel waits |
| Memory scanning | `ReadProcessMemory` reads payload bytes | On x64, `PAGE_EXECUTE` still allows reads (PTE limitation). True execute-only requires custom EPT. |

With all bypasses applied (manual syscalls + stack spoofing + `.text` trampolines +
timed page flipping), detection requires behavioral analysis of what the payload does
rather than where it lives.

Nobody runs `.data`-section-specific checks today.

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
