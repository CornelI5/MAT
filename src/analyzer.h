#ifndef ANALYZER_H
#define ANALYZER_H

#include <windows.h>

void print_header(const char* title);
void print_compile_time(DWORD timestamp);
void calculate_md5(char* filename);
void analyze_pe(char* filename);

#endif
