#ifndef __XDP_BYPASSLIB_H
#define __XDP_BYPASSLIB_H

#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>
#include <getopt.h>

#include "tools/lib/bpf/bpf.h"
#include "tools/lib/bpf/libbpf.h"
#include "libbpf.h"
#include "bpf_util.h"

#include "xdp_bypass.h"

typedef struct t_bypass_ctx {
    int v4_fd;
    int v6_fd;
    unsigned int nr_cpus;
} bypass_ctx;

bypass_ctx * xdp_bypass_init()
{
    bypass_ctx *ctx;
    ctx = malloc(sizeof(bypass_ctx));
    memset(ctx, 0, sizeof(bypass_ctx));
    ctx->nr_cpus = bpf_num_possible_cpus();
    return ctx;
}

void xdp_bypass_close(bypass_ctx *ctx)
{
    if(ctx->v4_fd > 0) {
        close(ctx->v4_fd);
        ctx->v4_fd = 0;
    }
    if(ctx->v6_fd > 0) {
        close(ctx->v6_fd);
        ctx->v6_fd = 0;
    }
}
//FIXME: what to do with errno?
int xdp_bypass_open_v4(bypass_ctx *ctx)
{
    if(ctx->v4_fd > 0) {
        return 0;
    }
    int fd = bpf_obj_get(PIN_PATH "/flow_table_v4");
    if (fd < 0) {
        printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
               PIN_PATH "/flow_table_v4", errno, strerror(errno));
        return fd;
    }
    ctx->v4_fd = fd;

    return 0;
}
int xdp_bypass_open_v6(bypass_ctx *ctx)
{
    if(ctx->v6_fd > 0) {
        return 0;
    }
    int fd = bpf_obj_get(PIN_PATH "/flow_table_v6");
    if (fd < 0) {
        printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
               PIN_PATH "/flow_table_v6", errno, strerror(errno));
        return fd;
    }
    ctx->v6_fd = fd;

    return 0;
}

static int xdp_bypass_v4(bypass_ctx *ctx, int ip_proto, char *src, int sport, char *dst, int dport)
{
    struct pair values[ctx->nr_cpus];
    struct flowv4_keys key;
    struct timespec curtime;
    int res;
    int i;

    /* Convert IP-string into 32-bit network byte-order value */
    res = inet_pton(AF_INET, src, &(key.src));
    if (res <= 0) {
        if (res == 0)
            fprintf(stderr,
                "ERR: IPv4 \"%s\" not in presentation format\n",
                src);
        else
            perror("inet_pton");
        return -1;
    }

    /* Convert IP-string into 32-bit network byte-order value */
    res = inet_pton(AF_INET, dst, &(key.dst));
    if (res <= 0) {
        if (res == 0)
            fprintf(stderr,
                "ERR: IPv4 \"%s\" not in presentation format\n",
                dst);
        else
            perror("inet_pton");
        return -1;
    }
    key.port16[0] = htons(sport);
    key.port16[1] = htons(dport);
    key.ip_proto = ip_proto;

    clock_gettime(CLOCK_MONOTONIC, &curtime);

    for(i=0; i < ctx->nr_cpus ; i++) {
        values[i].time = curtime.tv_sec * 1000000000;
        values[i].packets = 0;
        values[i].bytes = 0;
        //values[i].log_after = 0;
    }
    res=xdp_bypass_open_v4(ctx);
    if(res != 0) {
        return -1;
    }

    res = bpf_map_update_elem(ctx->v4_fd, &key, values, BPF_NOEXIST);
    if (res != 0) { /* 0 == success */
        if (errno == 17) {
            fprintf(stderr, "Already Bypassed\n");
            return EXIT_OK;
        }
        /* next caller will reopen */
        xdp_bypass_close(ctx);
        return EXIT_FAIL_MAP_KEY;
    }
    return EXIT_OK;
}
static int xdp_bypass_v6(bypass_ctx *ctx, int ip_proto, char *src, int sport, char *dst, int dport)
{
    /* FIXME: TODO */
    return -1;
}

/* FIXME: something in posix for this? */
int ip_family_from_string(char *s)
{
    if (strchr(s, '.') != NULL) return 4;
    if (strchr(s, ':') != NULL) return 6;
    return 0;
}

static int xdp_bypass(bypass_ctx *ctx, int ip_proto, char *src, int sport, char *dst, int dport)
{
    int family = ip_family_from_string(src);
    switch(family) {
        case 4:
            return xdp_bypass_v4(ctx, ip_proto, src, sport, dst, dport);
        case 6:
            return xdp_bypass_v6(ctx, ip_proto, src, sport, dst, dport);
        default:
            /* FIXME: what do? */
            return -1;
    }
}
#endif
