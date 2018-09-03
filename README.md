Experimental XDP bypass code.

I am trying to replicate what https://suricata.readthedocs.io/en/latest/capture-hardware/ebpf-xdp.html can do
in a standalone project.

Currently this is mostly code imported from https://github.com/netoptimizer/prototype-kernel with a few
bits copied from https://github.com/OISF/suricata/blob/master/ebpf/xdp_filter.c

# xdp_autocutoff

This is a PoC that implements automatic flow cutoff directly inside the kernel.  In the long term,
this is probably less useful than exposing a `bypass_flow` function to
userspace, but for now this will enable testing of unmodified applications to
see how they react when flows are cutoff.

## Usage:

    sudo sysctl net/core/bpf_jit_enable=1
    make && sudo ./xdp_autocutoff --ifname p1p1

NOTE: this will COMPLETELY DROP packets inside the kernel, so if you run this
remotely on your public interface your ssh connection will die after a few
minutes(you'll be able to reconnect).  This is intended to be ran on an
interface connected to a SPAN port or tap.

Some knobs you can change in xdp_autocutoff_kern.c are

    #define MAX_FLOWS 512*1024
    #define CUTOFF_PACKETS 1024
    #define CUTOFF_BYTES 512*1024

# xdp_bypass

This implements manual flow cutoff by using a BPF map exported to userspace.

## Usage:

    sudo sysctl net/core/bpf_jit_enable=1
    sudo   mount -t bpf bpf /sys/fs/bpf/
    make && sudo ./xdp_bypass --ifname p1p1

    #shunt a flow
    sudo ./xdp_bypass_cli tcp 10.10.10.1 1234 192.168.100.1 80

There is an example for Bro in [bypass.bro](bro/bypass.bro).  This should be
ported to a BIF that uses xdp_bypass_lib.h directly.

The cli does not need to be ran as root if you change the permissions on

    /sys/fs/bpf/autocutoff/flow_table_v4
    /sys/fs/bpf/autocutoff/flow_table_v6

after they are created.

Currently the two XDP programs use the same BPF maps to make testing easier,
but it will likely be renamed later.
