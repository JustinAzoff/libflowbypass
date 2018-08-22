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

int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0) {
        printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
               file, errno, strerror(errno));
        exit(EXIT_FAIL_MAP_FILE);
    }
    return fd;
}

static int xdp_bypass_v4(int fd, int ip_proto, char *src, int sport, char *dst, int dport)
{
    unsigned int nr_cpus = bpf_num_possible_cpus();
    struct pair values[nr_cpus];
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

    for(i=0; i < nr_cpus ; i++) {
        values[i].time = curtime.tv_sec * 1000000000;
        values[i].packets = 0;
        values[i].bytes = 0;
        //values[i].log_after = 0;
    }

    res = bpf_map_update_elem(fd, &key, values, BPF_NOEXIST);
    if (res != 0) { /* 0 == success */
        if (errno == 17) {
            fprintf(stderr, ": Already Bypassed\n");
            return EXIT_OK;
        }
        fprintf(stderr, "\n");
        return EXIT_FAIL_MAP_KEY;
    }
    return EXIT_OK;
}
#endif
