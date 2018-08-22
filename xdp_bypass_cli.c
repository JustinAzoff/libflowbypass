#include "xdp_bypass_lib.h"

int main(int argc, char **argv) {
    int fd = 0;
    int res;
    if(argc < 5) {
        fprintf(stderr, "Usage: %s src sport dst dport\n", argv[0]);
        return 1;
    }
    fd = open_bpf_map(PIN_PATH "/flow_table_v4");

    char *src = argv[1];
    int sport = atoi(argv[2]);
    char *dst = argv[3];
    int dport = atoi(argv[4]);

    res = xdp_bypass_v4(fd, src, sport, dst, dport);
    printf("Res: %d\n", res);
    return res;
}
