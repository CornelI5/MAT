#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <time.h>

#pragma comment(lib, "advapi32.lib")

void print_header(const char* title) {
    printf("\n[+] %s\n", title);
    printf("------------------------------------------\n");
}

void print_compile_time(DWORD timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("Compile Time    : %s (UTC)\n", buffer);
}

void calculate_md5(char* filename) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) { 
        printf("[-] Failed to open file for hashing.\n"); 
        return; 
    }

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            BYTE buffer[1024];
            DWORD bytesRead = 0;
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                CryptHashData(hHash, buffer, bytesRead, 0);
            }
            BYTE hash[16];
            DWORD hashLen = 16;
            CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
            
            printf("MD5 Hash        : ");
            for (int i = 0; i < 16; i++) printf("%02x", hash[i]);
            printf("\n");
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { 
        printf("Usage: MAT.exe <path_to_pe_file>\n"); 
        return 1; 
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { 
        printf("[-] Error: Could not open file.\n"); 
        return 1; 
    }

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID lpBase = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)lpBase;
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { 
        printf("[-] Error: Invalid PE format.\n"); 
        return 1; 
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + dos->e_lfanew);

    printf("=== MAT v0.2: Static Analysis Tool ===\n");
    print_header("Basic Information");
    printf("Target File     : %s\n", argv[1]);
    printf("Architecture    : %s\n", (nt->FileHeader.Machine == 0x8664) ? "x64" : "x86");
    printf("Entry Point     : 0x%X\n", nt->OptionalHeader.AddressOfEntryPoint);
    print_compile_time(nt->FileHeader.TimeDateStamp);
    calculate_md5(argv[1]);

    print_header("Section Table");
    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        printf("[%d] %-8.8s | RawSize: 0x%06X | VAddr: 0x%06X\n", 
                i+1, sect[i].Name, sect[i].SizeOfRawData, sect[i].VirtualAddress);
    }

    UnmapViewOfFile(lpBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}
