#ifndef __XDP_BYPASS_MAPS_H
#define __XDP_BYPASS_MAPS_H

struct flowv4_keys {
    __u32 src;
    __u32 dst;
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u32 ip_proto;
} __attribute__((__aligned__(8)));

struct flowv6_keys {
    __u32 src[4];
    __u32 dst[4];
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
    __u64 log_after;
} __attribute__((__aligned__(8)));

#endif
