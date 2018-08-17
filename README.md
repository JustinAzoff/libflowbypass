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

    make && sudo ./xdp_autocutoff --ifname p1p1

NOTE: this will COMPLETELY DROP packets inside the kernel, so if you run this
remotely on your public interface your ssh connection will die after a few
minutes(you'll be able to reconnect).  This is intended to be ran on an
interface connected to a SPAN port or tap.

Some knobs you can change in xdp_autocutoff_kern.c are

    #define MAX_FLOWS 512*1024
    #define CUTOFF_PACKETS 1024
    #define CUTOFF_BYTES 512*1024
