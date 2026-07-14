#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>

typedef struct { uint16_t e_magic; uint32_t e_lfanew; } DOS_HEADER;
typedef struct { uint32_t Signature; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PtrSym; uint32_t NumSym; uint16_t SizeOpt; uint16_t Char; } FILE_HEADER;
typedef struct { char Name[8]; uint32_t VSize; uint32_t VAddr; uint32_t SizeRaw; uint32_t PtrRaw; uint32_t PtrReloc; uint32_t PtrLine; uint16_t NumReloc; uint16_t NumLine; uint32_t Characteristics; } SECTION_HEADER;

void print_header(const char* title);
void print_compile_time(uint32_t timestamp);
void calculate_md5(const char* filename);
void analyze_pe(const char* filename);
uint32_t rva_to_offset(uint32_t rva, SECTION_HEADER* sections, int num_sections);
void print_import_table(void* lpBase, uint32_t rva, SECTION_HEADER* sections, int num_sections);
void run_backit_check(SECTION_HEADER* sections, int num_sections);

#endif
