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
#include <dlfcn.h>

uint32_t rva_to_offset(uint32_t rva, SECTION_HEADER* sections, int num_sections) {
    for (int i = 0; i < num_sections; i++) {
        if (rva >= sections[i].VAddr && rva < sections[i].VAddr + sections[i].VSize)
            return rva - sections[i].VAddr + sections[i].PtrRaw;
    }
    return 0;
}

void print_header(const char* title) {
    printf("\n[+] %s\n--------------------------------------------------------------------------\n", title);
}

void calculate_md5(const char* filename, char* md5_out) {
    unsigned char c[MD5_DIGEST_LENGTH];
    FILE *f = fopen(filename, "rb");
    MD5_CTX ctx; unsigned char data[1024]; int b;
    if (!f) { strcpy(md5_out, "N/A"); return; }
    MD5_Init(&ctx); while ((b = fread(data, 1, 1024, f)) != 0) MD5_Update(&ctx, data, b);
    MD5_Final(c, &ctx);
    fclose(f);
    for(int i=0; i<MD5_DIGEST_LENGTH; i++) sprintf(&md5_out[i*2], "%02x", c[i]);
    md5_out[32] = '\0';
}

void run_backit_check(SECTION_HEADER* sections, int num_sections, char* result_buf, size_t buf_size) {
    result_buf[0] = '\0';
    char temp[256];
    int alert_count = 0;
    for (int i = 0; i < num_sections; i++) {
        if ((sections[i].Characteristics & 0x20000000) && (sections[i].Characteristics & 0x80000000)) {
            snprintf(temp, sizeof(temp), " -> [!] ALERT: Section '%-8.8s' is RWX (Read-Write-Execute).\n", sections[i].Name);
            strncat(result_buf, temp, buf_size - strlen(result_buf) - 1);
            alert_count++;
        }
    }
    if (alert_count == 0) {
        strncpy(result_buf, " -> [OK] No suspicious RWX sections found.\n", buf_size - 1);
    }
}

void run_rule_engine(const char* rule_path, SECTION_HEADER* sections, int num_sections, char* rule_result, size_t buf_size) {
    rule_result[0] = '\0';
    if (!rule_path) {
        strncpy(rule_result, " -> No rules provided.\n", buf_size - 1);
        return;
    }
    FILE *f = fopen(rule_path, "r");
    if (!f) {
        strncpy(rule_result, " -> [-] Failed to open rule file.\n", buf_size - 1);
        return;
    }
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (strlen(line) == 0) continue;
        
        for (int i = 0; i < num_sections; i++) {
            if (strncasecmp(sections[i].Name, line, 8) == 0) {
                char alert[256];
                snprintf(alert, sizeof(alert), " -> [!] RULE MATCHED: Section '%s' detected!\n", line);
                strncat(rule_result, alert, buf_size - strlen(rule_result) - 1);
            }
        }
    }
    fclose(f);
    if (strlen(rule_result) == 0) {
        strncpy(rule_result, " -> [OK] Rule scan clean. No signatures matched.\n", buf_size - 1);
    }
}

void execute_plugin(const char* plugin_path, const char* target_file) {
    if (!plugin_path) return;
    printf("\n[*] Loading external plugin: %s\n", plugin_path);
    void* handle = dlopen(plugin_path, RTLD_LAZY);
    if (!handle) {
        printf("[-] Plugin error: %s\n", dlerror());
        return;
    }
    void (*run_plugin)(const char*) = dlsym(handle, "run_plugin");
    char *error = dlerror();
    if (error != NULL) {
        printf("[-] Resolve error: %s\n", error);
        dlclose(handle);
        return;
    }
    printf("[+] Executing plugin hook...\n");
    run_plugin(target_file);
    dlclose(handle);
}

void write_json_report(const char* out_path, const char* filename, const char* md5, const char* arch, SECTION_HEADER* sections, int num_sections, const char* backit_log, const char* rule_log) {
    if (!out_path) return;
    FILE *f = fopen(out_path, "w");
    if (!f) return;
    fprintf(f, "{\n  \"target_file\": \"%s\",\n  \"md5\": \"%s\",\n  \"architecture\": \"%s\",\n  \"sections\": [\n", filename, md5, arch);
    for (int i = 0; i < num_sections; i++) {
        fprintf(f, "    { \"name\": \"%-8.8s\", \"size\": %d, \"flags\": \"0x%08X\" }%s\n", 
                sections[i].Name, sections[i].SizeRaw, sections[i].Characteristics, (i == num_sections - 1) ? "" : ",");
    }
    fprintf(f, "  ],\n  \"backit_integrity\": \"%s\",\n  \"rules_matched\": \"%s\"\n}\n", backit_log, rule_log);
    fclose(f);
    printf("[+] JSON Report saved to %s\n", out_path);
}

void write_txt_report(const char* out_path, const char* filename, const char* md5, const char* arch, SECTION_HEADER* sections, int num_sections, const char* backit_log, const char* rule_log) {
    if (!out_path) return;
    FILE *f = fopen(out_path, "w");
    if (!f) return;
    fprintf(f, "MAT ANALYSIS REPORT\n===================\nTarget: %s\nMD5: %s\nArch: %s\n\nSections:\n", filename, md5, arch);
    for (int i = 0; i < num_sections; i++) {
        fprintf(f, "  [%d] %-8.8s | RawSize: 0x%06X | Flags: 0x%08X\n", i+1, sections[i].Name, sections[i].SizeRaw, sections[i].Characteristics);
    }
    fprintf(f, "\nIntegrity Results:\n%s\nRule Engine Results:\n%s", backit_log, rule_log);
    fclose(f);
    printf("[+] TXT Report saved to %s\n", out_path);
}

void analyze_pe(const char* filename, const char* json_path, const char* txt_path, const char* rule_path, const char* plugin_path) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) { printf("[-] Error: Cannot open target file.\n"); return; }
    struct stat st; fstat(fd, &st);
    void* lpBase = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    DOS_HEADER* dos = (DOS_HEADER*)lpBase;
    if (dos->e_magic != 0x5A4D) { printf("[-] Invalid PE Format.\n"); munmap(lpBase, st.st_size); close(fd); return; }
    
    FILE_HEADER* fh = (FILE_HEADER*)((char*)lpBase + dos->e_lfanew + 4);
    SECTION_HEADER* sect = (SECTION_HEADER*)((char*)fh + 20 + fh->SizeOpt);
    
    char md5[33];
    calculate_md5(filename, md5);
    const char* arch = (fh->Machine == 0x8664) ? "x64" : "x86";

    printf("Target File     : %s\n", filename);
    printf("Architecture    : %s\n", arch);
    printf("MD5 Hash        : %s\n", md5);
    
    printf("\nSection Table:\n");
    for (int i = 0; i < fh->NumberOfSections; i++) {
        printf("[%d] %-8.8s | RawSize: 0x%06X | Flags: 0x%08X\n", i+1, sect[i].Name, sect[i].SizeRaw, sect[i].Characteristics);
    }

    char backit_log[1024];
    run_backit_check(sect, fh->NumberOfSections, backit_log, sizeof(backit_log));
    printf("\n[+] Integrity:\n%s", backit_log);

    char rule_log[1024];
    run_rule_engine(rule_path, sect, fh->NumberOfSections, rule_log, sizeof(rule_log));
    printf("\n[+] Signature Scan:\n%s", rule_log);

    write_json_report(json_path, filename, md5, arch, sect, fh->NumberOfSections, backit_log, rule_log);
    write_txt_report(txt_path, filename, md5, arch, sect, fh->NumberOfSections, backit_log, rule_log);

    execute_plugin(plugin_path, filename);

    munmap(lpBase, st.st_size); close(fd);
}
