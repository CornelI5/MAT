#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>

typedef struct { uint16_t e_magic; uint32_t e_lfanew; } DOS_HEADER;
typedef struct { uint32_t Signature; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PtrSym; uint32_t NumSym; uint16_t SizeOpt; uint16_t Char; } FILE_HEADER;
typedef struct { char Name[8]; uint32_t VSize; uint32_t VAddr; uint32_t SizeRaw; uint32_t PtrRaw; uint32_t PtrReloc; uint32_t PtrLine; uint16_t NumReloc; uint16_t NumLine; uint32_t Characteristics; } SECTION_HEADER;

uint32_t rva_to_offset(uint32_t rva, SECTION_HEADER* sections, int num_sections);
void calculate_md5(const char* filename, char* md5_out);
void analyze_pe(const char* filename, const char* json_path, const char* txt_path, const char* rule_path, const char* plugin_path);

void print_header(const char* title);
void run_backit_check(SECTION_HEADER* sections, int num_sections, char* result_buf, size_t buf_size);
void run_rule_engine(const char* rule_path, SECTION_HEADER* sections, int num_sections, char* rule_result, size_t buf_size);
void execute_plugin(const char* plugin_path, const char* target_file);

void write_json_report(const char* out_path, const char* filename, const char* md5, const char* arch, SECTION_HEADER* sections, int num_sections, const char* backit_log, const char* rule_log);
void write_txt_report(const char* out_path, const char* filename, const char* md5, const char* arch, SECTION_HEADER* sections, int num_sections, const char* backit_log, const char* rule_log);

#endif
