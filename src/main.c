#include "analyzer.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc < 2) { printf("Usage: ./MAT <file>\n"); return 1; }
    print_header("MAT Linux Native Edition");
    analyze_pe(argv[1]);
    return 0;
}
