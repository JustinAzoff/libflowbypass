#ifndef __XDP_BYPASS_H
#define __XDP_BYPASS_H

#define MAX_FLOWS 512*1024
#define FLOW_TIMEOUT_SECONDS 10

#define EXIT_OK         0
#define EXIT_FAIL       1
#define EXIT_FAIL_OPTION    2
#define EXIT_FAIL_XDP       3
#define EXIT_FAIL_MAP_KEY   4
#define EXIT_FAIL_MAP_FILE  5

#define PIN_PATH "/sys/fs/bpf/autocutoff"

#include "xdp_bypass_maps.h"

#endif
