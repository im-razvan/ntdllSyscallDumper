#include <Windows.h>
#include <fstream>

#if !defined(_M_X64)
#error "This code was made for the x64 architecture."
#endif

int main() {
    HMODULE mod = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (!dos) return 1;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 1;

    auto exp_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mod + exp_rva);
    DWORD* names = (DWORD*)((BYTE*)mod + exp_dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)mod + exp_dir->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)mod + exp_dir->AddressOfFunctions);

    std::ofstream csv("syscalls.csv");
    csv << "Syscall Name,ID\n";

    for (DWORD i = 0; i < exp_dir->NumberOfNames; i++) {
        char* name = (char*)((BYTE*)mod + names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;

        DWORD addr = funcs[ordinals[i]];
        BYTE* code = (BYTE*)mod + addr;

        /*
        mov r10, rcx
        mov eax, <SYSCALL_ID>

        4C 8B D1 B8 ? ? ? ?
        */
        if (*(DWORD*)code == 0xB8D18B4C && !(addr & 0x80000000)) {
            DWORD id = *(DWORD*)(code + 4);
            csv << name << "," << id << "\n";
        }
    }

    csv.close();

    return 0;
}
