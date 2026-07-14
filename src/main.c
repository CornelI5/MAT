#include "analyzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

void print_usage() {
    printf("==========================================================================\n");
    printf("                      MAT v1.0: Static Analysis Tool                      \n");
    printf("==========================================================================\n");
    printf("Usage: ./MAT [OPTIONS] -f <pe_file>\n\n");
    printf("Options:\n");
    printf("  -f, --file <path>      Path to target PE file (Required)\n");
    printf("  -j, --json <path>      Export analysis to JSON file\n");
    printf("  -t, --txt <path>       Export analysis to TXT report\n");
    printf("  -r, --rules <path>     Path to signature rules file\n");
    printf("  -p, --plugin <path>    Load external '.so' analysis plugin\n");
    printf("  -h, --help             Show this help information\n");
}

int main(int argc, char *argv[]) {
    int opt;
    char *filepath = NULL;
    char *json_out = NULL;
    char *txt_out = NULL;
    char *rule_path = NULL;
    char *plugin_path = NULL;

    struct option long_options[] = {
        {"file",   required_argument, 0, 'f'},
        {"json",   required_argument, 0, 'j'},
        {"txt",    required_argument, 0, 't'},
        {"rules",  required_argument, 0, 'r'},
        {"plugin", required_argument, 0, 'p'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "f:j:t:r:p:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'f': filepath = optarg; break;
            case 'j': json_out = optarg; break;
            case 't': txt_out = optarg; break;
            case 'r': rule_path = optarg; break;
            case 'p': plugin_path = optarg; break;
            case 'h': print_usage(); return 0;
            default: print_usage(); return 1;
        }
    }

    if (!filepath) {
        printf("[-] Error: File path target is required!\n");
        print_usage();
        return 1;
    }

    print_header("MAT Linux Core Engine Loaded");
    analyze_pe(filepath, json_out, txt_out, rule_path, plugin_path);

    return 0;
}
