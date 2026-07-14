#include "analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <openssl/md5.h>

uint32_t rva_to_offset(uint32_t rva, SECTION_HEADER* sections, int num_sections) {
    for (int i = 0; i < num_sections; i++) {
        if (rva >= sections[i].VAddr && rva < sections[i].VAddr + sections[i].VSize)
            return rva - sections[i].VAddr + sections[i].PtrRaw;
    }
    return 0;
}

void run_backit_check(SECTION_HEADER* sections, int num_sections) {
    printf("\n[+] Running 'Backit' Integrity Check...\n");
    for (int i = 0; i < num_sections; i++) {
        if ((sections[i].Characteristics & 0x20000000) && (sections[i].Characteristics & 0x80000000))
            printf(" -> [!] ALERT: Malicious Section '%-8.8s' is RWX (Read-Write-Execute).\n", sections[i].Name);
    }
}

void print_import_table(void* lpBase, uint32_t rva, SECTION_HEADER* sections, int num_sections) {
    uint32_t offset = rva_to_offset(rva, sections, num_sections);
    if (!offset) return;
    struct { uint32_t OFT, Time, Forward, Name, FT; } *imp = (void*)((char*)lpBase + offset);
    printf("\n[+] Import Table:\n");
    while (imp->Name != 0) {
        printf(" -> DLL: %s\n", (char*)lpBase + rva_to_offset(imp->Name, sections, num_sections));
        imp++;
    }
}

void print_header(const char* title) { printf("\n[+] %s\n----------------------------------\n", title); }

void calculate_md5(const char* filename) {
    unsigned char c[MD5_DIGEST_LENGTH];
    FILE *f = fopen(filename, "rb");
    MD5_CTX ctx; unsigned char data[1024]; int b;
    MD5_Init(&ctx); while ((b = fread(data, 1, 1024, f)) != 0) MD5_Update(&ctx, data, b);
    MD5_Final(c, &ctx);
    printf("MD5 Hash        : "); for(int i=0; i<MD5_DIGEST_LENGTH; i++) printf("%02x", c[i]);
    printf("\n"); fclose(f);
}

void analyze_pe(const char* filename) {
    int fd = open(filename, O_RDONLY); struct stat st; fstat(fd, &st);
    void* lpBase = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    DOS_HEADER* dos = (DOS_HEADER*)lpBase;
    if (dos->e_magic != 0x5A4D) { printf("[-] Invalid PE\n"); return; }
    FILE_HEADER* fh = (FILE_HEADER*)((char*)lpBase + dos->e_lfanew + 4);
    SECTION_HEADER* sect = (SECTION_HEADER*)((char*)fh + 20 + fh->SizeOpt);
    
    printf("Architecture    : %s\n", (fh->Machine == 0x8664) ? "x64" : "x86");
    calculate_md5(filename);
    for (int i = 0; i < fh->NumberOfSections; i++)
        printf("[%d] %-8.8s | RawSize: 0x%06X | Flags: 0x%08X\n", i+1, sect[i].Name, sect[i].SizeRaw, sect[i].Characteristics);
    
    print_import_table(lpBase, *(uint32_t*)((char*)fh + 96), sect, fh->NumberOfSections);
    run_backit_check(sect, fh->NumberOfSections);
    munmap(lpBase, st.st_size); close(fd);
}
