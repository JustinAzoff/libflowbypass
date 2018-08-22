#include "xdp_bypass_lib.h"

int main(int argc, char **arvc) {
    int fd = 0;
    int res;
    fd = open_bpf_map(PIN_PATH "/flow_table_v4");
    res = xdp_bypass_v4(fd, "192.168.2.1", 5001, "192.168.2.22", 5005);
    printf("Res: %d\n", res);
    return res;
}
