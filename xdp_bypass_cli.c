#include "xdp_bypass_lib.h"

int main(int argc, char **argv) {
    int res;
    if(argc < 6) {
        fprintf(stderr, "Usage: %s proto src sport dst dport\n", argv[0]);
        return 1;
    }

    char *proto = argv[1];
    int ip_proto;

    if(strcmp(proto, "tcp")==0) {
        ip_proto = IPPROTO_TCP;
    } else if(strcmp(proto, "udp")==0) {
        ip_proto = IPPROTO_UDP;
    } else {
        fprintf(stderr, "Invalid Proto. should be tcp or udp\n");
        return 1;
    }

    char *src = argv[2];
    int sport = atoi(argv[3]);
    char *dst = argv[4];
    int dport = atoi(argv[5]);

    bypass_ctx* ctx = xdp_bypass_init();
    res = xdp_bypass(ctx, ip_proto, src, sport, dst, dport);
    printf("Res: %d\n", res);
    xdp_bypass_close(ctx);
    return res;
}
