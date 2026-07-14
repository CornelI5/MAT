#include <stdio.h>
#include <windows.h>

void print_header(const char* title) {
    printf("\n[+] %s\n", title);
    printf("------------------------------------------\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: MAT.exe <pe_file>\n");
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Gagal membuka file: %s\n", argv[1]);
        return 1;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lpBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Bukan format PE yang valid!\n");
        return 1;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dos->e_lfanew);

    printf("=== MAT v0.1: Static Analyzer ===\n");
    printf("Target: %s\n", argv[1]);
    
    print_header("Basic Information");
    printf("Machine: %s\n", (nt->FileHeader.Machine == 0x8664) ? "x64" : "x86");
    printf("Entry Point: 0x%X\n", nt->OptionalHeader.AddressOfEntryPoint);
    printf("Sections Count: %d\n", nt->FileHeader.NumberOfSections);

    print_header("Section Table");
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        printf("Section: %-8.8s | RawSize: 0x%X | VAddr: 0x%X\n", 
                sect[i].Name, sect[i].SizeOfRawData, sect[i].VirtualAddress);
    }

    UnmapViewOfFile(lpBase);
    CloseHandle(hMap);
    CloseHandle(hFile);

    return 0;
}
