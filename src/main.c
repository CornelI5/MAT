#include <stdio.h>
#include <windows.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <path_to_pe_file>\n", argv[0]);
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Gagal buka file. Error code: %d\n", GetLastError());
        return 1;
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID lpBaseAddress = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Bukan file PE (Executable) yang valid!\n");
        return 1;
    }

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBaseAddress + dosHeader->e_lfanew);

    printf("[+] Analisis File: %s\n", argv[1]);
    printf("[+] DOS Magic: 0x%X\n", dosHeader->e_magic);
    printf("[+] Entry Point: 0x%X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("[+] Image Base: 0x%llX\n", (unsigned long long)ntHeaders->OptionalHeader.ImageBase);
    printf("[+] Number of Sections: %d\n", ntHeaders->FileHeader.NumberOfSections);

    UnmapViewOfFile(lpBaseAddress);
    CloseHandle(hMap);
    CloseHandle(hFile);

    printf("[+] Selesai.\n");
    return 0;
}
