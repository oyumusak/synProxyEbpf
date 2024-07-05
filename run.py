from bcc import BPF
from time import sleep

with open("synproxy.bpf.c", "r") as file:
	program = file.read()

b = BPF(text=program)
b.attach_xdp(dev="enp0s3", fn=b.load_func("syn_proxy", BPF.XDP))

b.trace_print()
