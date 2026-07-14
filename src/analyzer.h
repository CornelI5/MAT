#ifndef ANALYZER_H
#define ANALYZER_H

#include <stdint.h>

typedef struct {
    uint16_t e_magic;
    uint32_t e_lfanew;
} DOS_HEADER;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} FILE_HEADER;

typedef struct {
    char Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLineNumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLineNumbers;
    uint32_t Characteristics;
} SECTION_HEADER;

void print_header(const char* title);
void print_compile_time(uint32_t timestamp);
void calculate_md5(const char* filename);
void analyze_pe(const char* filename);
uint32_t rva_to_offset(uint32_t rva, SECTION_HEADER* sections, int num_sections);
void print_import_table(void* lpBase, uint32_t rva, uint32_t size, SECTION_HEADER* sections, int num_sections);

#endif
