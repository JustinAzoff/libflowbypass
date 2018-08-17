/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
static const char *__doc__=
 " XDP example of cutting off flows after a packet or byte limit.";

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

#include "libbpf.h"
#include "bpf_load.h"
#include "bpf_util.h"

static int ifindex = -1;

static void int_exit(int sig)
{
    fprintf(stderr, "Interrupted: Removing XDP program on ifindex:%d\n",
        ifindex);
    if (ifindex > -1)
        set_link_xdp_fd(ifindex, -1, 0);
    exit(0);
}

static const struct option long_options[] = {
    {"help",    no_argument,        NULL, 'h' },
    {"ifname",  required_argument,  NULL, 'i' },
    {0, 0, NULL,  0 }
};

/* Exit return codes */
#define EXIT_OK         0
#define EXIT_FAIL       1
#define EXIT_FAIL_OPTION    2
#define EXIT_FAIL_XDP       3

static void usage(char *argv[])
{
    int i;
    printf("\nDOCUMENTATION:\n%s\n", __doc__);
    printf("\n");
    printf(" Usage: %s (options-see-below)\n",
           argv[0]);
    printf(" Listing options:\n");
    for (i = 0; long_options[i].name != 0; i++) {
        printf(" --%-12s", long_options[i].name);
        if (long_options[i].flag != NULL)
            printf(" flag (internal value:%d)",
                   *long_options[i].flag);
        else
            printf(" short-option: -%c",
                   long_options[i].val);
        printf("\n");
    }
    printf("\n");
}

#define MAX_KEYS    256

struct ttl_stats {
    __u64 data[MAX_KEYS];
};

struct flowv4_keys {
    __u32 src;
    __u32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u32 ip_proto;
} __attribute__((__aligned__(8)));

struct pair {
    __u64 time;
    __u64 packets;
    __u64 bytes;
} __attribute__((__aligned__(8)));


#define FLOW_TIMEOUT 10

#define V4_IP_FORMAT "%d.%d.%d.%d"
#define V4_IP_FORMAT_V(ip) \
    (ip & 0xFF), \
    ((ip >> 8) & 0xFF), \
    ((ip >> 16) & 0xFF), \
    ((ip >> 24) & 0xFF)


static bool expire_flows()
{
    struct flowv4_keys key = {}, next_key;
    unsigned int nr_cpus = bpf_num_possible_cpus();
    //printf("CPUS: %d\n", nr_cpus);
    struct pair values[nr_cpus];
    int i;
    struct timespec curtime;
    clock_gettime(CLOCK_MONOTONIC, &curtime);
    int flows_total=0, flows_expired=0;

    while (bpf_map_get_next_key(map_fd[0], &key, &next_key) == 0) {
        int res = bpf_map_lookup_elem(map_fd[0], &key, values);
        if (res < 0) {
            //printf("no entry in v4 table for %d -> %d\n", key.port16[0], key.port16[1]);
            key = next_key;
            continue;
        }

        flows_total++;
        for (i = 0; i < nr_cpus; i++) {
            if(values[i].time) {
                int age = curtime.tv_sec - values[i].time / 1000000000;
                if (age > FLOW_TIMEOUT) {
                    bpf_map_delete_elem(map_fd[0], &key);
                    printf("Expired Flow v4: "V4_IP_FORMAT":%d -> "V4_IP_FORMAT":%d ",
                        V4_IP_FORMAT_V(key.src), ntohs(key.port16[0]), V4_IP_FORMAT_V(key.dst), ntohs(key.port16[1]));
                    printf("t=%llu packets=%llu bytes=%llu\n", values[i].time / 1000000000, values[i].packets, values[i].bytes);
                    flows_expired++;
                }
            }

        }
        key = next_key;
    }
    printf("Flows: total=%d expired=%d\n", flows_total, flows_expired);
    return false;
}

static void flows_poll(int interval)
{
    while (1) {
        expire_flows();
        sleep(interval);
    }
}

int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    char filename[256];
    int longindex = 0;
    int opt;
    char *ifname=NULL;

    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hi:",
                  long_options, &longindex)) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'h':
        default:
            usage(argv);
            return EXIT_FAIL_OPTION;
        }
    }
    /* Required options */
    if (ifname==NULL) {
        printf("**Error**: required option --ifname missing");
        usage(argv);
        return EXIT_FAIL_OPTION;
    }
    if((ifindex=if_nametoindex(ifname)) == 0) {
        perror("Can't find interface");
        return EXIT_FAIL_OPTION;
    }
    /* Required options */
    if (ifindex == -1) {
        printf("**Error**: required option --ifindex missing");
        usage(argv);
        return EXIT_FAIL_OPTION;
    }

    /* Increase resource limits */
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
        return 1;
    }

    if (load_bpf_file(filename)) {
        printf("%s", bpf_log_buf);
        return 1;
    }

    if (!prog_fd[0]) {
        printf("load_bpf_file: %s\n", strerror(errno));
        return 1;
    }

    /* Remove XDP program when program is interrupted */
    signal(SIGINT, int_exit);

    if (set_link_xdp_fd(ifindex, prog_fd[0], 0) < 0) {
        printf("link set xdp fd failed\n");
        return EXIT_FAIL_XDP;
    }

#define DEBUG 1
#ifdef  DEBUG
    {
    char msg[] =
        "\nDebug outout avail via:\n"
        " sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n";
    printf(msg);
    }
#endif

    flows_poll(5);

    return EXIT_OK;
}
