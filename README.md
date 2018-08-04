BPF Examples
============

Simple BPF examples.

packetcount
-----------

Adapted from `man 2 bpf`.  The original example in the man page does
not compile.  This example has all the necessary helpers to make it
working.

Build the target with `make` and run it with `packetcount <ifname>`.

stacksnoop
----------

Adapted from the `stacksnoop.py` example in the
[bcc](https://github.com/iovisor/bcc) project.  This example is
implemented in C to demonstrated the following development process:

1. develop kernel eBPF filter in C,
2. use llvm to compile the kernel eBPF to an object file,
3. userspace application load the eBPF object file to kernel.

Build the target with `make` and run it with `stacksnoop <func_name>`.

TODO
----

Proper cleanups and etc.
