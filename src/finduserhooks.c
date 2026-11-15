/*
 * finduserhooks [module] - flag exported functions whose prologue looks hooked.
 *
 * Heuristics: relative jmp (E9), short jmp (EB), indirect jmp (FF 25 /
 * 48 FF 25), or mov rax,imm64; jmp rax.  Legitimate hot-patch stubs also
 * match, so treat hits as review candidates, not proof of a hook.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "helpers.h"

static int looks_hooked(const unsigned char *p, int n)
{
    if (n >= 5 && p[0] == 0xE9) return 1;
    if (n >= 2 && p[0] == 0xEB) return 1;
    if (n >= 6 && p[0] == 0xFF && p[1] == 0x25) return 1;
    if (n >= 7 && p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25) return 1;
    if (n >= 12 && p[0] == 0x48 && p[1] == 0xB8 &&
        p[10] == 0xFF && p[11] == 0xE0) return 1;
    return 0;
}

static void scan_module(const char *name)
{
    HMODULE base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dir;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names, *funcs;
    WORD *ords;
    DWORD i, hits = 0;

    base = KERNEL32$GetModuleHandleA(name);
    if (!base) {
        BeaconPrintf(CALLBACK_ERROR, "%s is not loaded\n", name);
        return;
    }

    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) {
        BeaconPrintf(CALLBACK_OUTPUT, "%s: no exports\n", name);
        return;
    }

    exp   = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)base + dir->VirtualAddress);
    names = (DWORD *)((BYTE *)base + exp->AddressOfNames);
    ords  = (WORD *)((BYTE *)base + exp->AddressOfNameOrdinals);
    funcs = (DWORD *)((BYTE *)base + exp->AddressOfFunctions);

    BeaconPrintf(CALLBACK_OUTPUT, "%s exports (%lu)\n", name,
                 (unsigned long)exp->NumberOfNames);

    for (i = 0; i < exp->NumberOfNames; i++) {
        const char *fn = (const char *)((BYTE *)base + names[i]);
        BYTE *addr = (BYTE *)base + funcs[ords[i]];

        if (addr < (BYTE *)base + dir->VirtualAddress ||
            addr >= (BYTE *)base + dir->VirtualAddress + dir->Size)
            continue;   /* forwarder */

        if (looks_hooked(addr, 12)) {
            BeaconPrintf(CALLBACK_OUTPUT,
                         "  %-40s %p  %02x %02x %02x %02x %02x\n",
                         fn, addr, addr[0], addr[1], addr[2], addr[3], addr[4]);
            hits++;
            if (hits >= 50) {
                BeaconPrintf(CALLBACK_OUTPUT, "  ... (truncated)\n");
                break;
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "  suspicious prologues: %lu\n\n",
                 (unsigned long)hits);
}

void go(char *args, int alen)
{
    datap parser;
    char *mod = "";
    int mlen = 0;

    if (args && alen > 0) {
        BeaconDataParse(&parser, args, alen);
        mod = BeaconDataExtract(&parser, &mlen);
        if (!mod) mod = "";
    }

    if (mod[0]) {
        scan_module(mod);
        return;
    }

    scan_module("ntdll.dll");
    scan_module("kernel32.dll");
    scan_module("kernelbase.dll");
    scan_module("advapi32.dll");
    scan_module("user32.dll");
}
