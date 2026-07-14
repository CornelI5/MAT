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
} FILE_HEADER;

void print_header(const char* title);
void analyze_pe(const char* filename);

#endif
