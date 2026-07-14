#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/md5.h>

typedef struct {
    uint16_t e_magic;
    uint32_t e_lfanew;
} DOS_HEADER;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} FILE_HEADER;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t Characteristics;
} SECTION_HEADER;

void print_header(const char* title) {
    printf("\n[+] %s\n", title);
    printf("--------------------------------------------------------------------------\n");
}

void print_compile_time(uint32_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    char buffer[26];
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    printf("Compile Time    : %s (UTC)\n", buffer);
}

void calculate_md5(const char* filename) {
    unsigned char c[MD5_DIGEST_LENGTH];
    FILE *file = fopen(filename, "rb");
    MD5_CTX mdContext;
    unsigned char data[1024];
    int bytes;

    if (!file) { printf("[-] Failed to open file for hashing.\n"); return; }
    MD5_Init(&mdContext);
    while ((bytes = fread(data, 1, 1024, file)) != 0) MD5_Update(&mdContext, data, bytes);
    MD5_Final(c, &mdContext);
    
    printf("MD5 Hash        : ");
    for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", c[i]);
    printf("\n");
    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc < 2) { printf("Usage: ./MAT <path_to_pe_file>\n"); return 1; }

    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    void* lpBase = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    
    DOS_HEADER* dos = (DOS_HEADER*)lpBase;
    if (dos->e_magic != 0x5A4D) { printf("[-] Error: Not a valid PE file.\n"); return 1; }

    FILE_HEADER* fh = (FILE_HEADER*)((char*)lpBase + dos->e_lfanew + 4);

    print_header("MAT v0.2: Linux Native Static Analyzer");
    printf("Target File     : %s\n", argv[1]);
    printf("Architecture    : %s\n", (fh->Machine == 0x8664) ? "x64" : "x86");
    print_compile_time(fh->TimeDateStamp);
    calculate_md5(argv[1]);

    print_header("Section Table");
    SECTION_HEADER* sect = (SECTION_HEADER*)((char*)fh + sizeof(FILE_HEADER) + 224); 
    for (int i = 0; i < fh->NumberOfSections; i++) {
        printf("[%d] %-8.8s | RawSize: 0x%06X | VAddr: 0x%06X | Flags: 0x%08X\n", 
                i+1, sect[i].Name, sect[i].SizeOfRawData, sect[i].VirtualAddress, sect[i].Characteristics);
    }

    munmap(lpBase, st.st_size);
    close(fd);
    return 0;
}
