#include "istcp.h"

BPF_HASH(ip_list);

int syn_proxy(struct xdp_md *ctx)
{
    struct tcphdr *tcphdr = NULL;
    struct iphdr *iphdr = NULL;
    unsigned long long *tmp;
    unsigned long long counter;
    void *data;

    bpf_trace_printk("helloo \\n");
    tcphdr = (struct tcphdr *)is_tcp(ctx);
    if (!tcphdr)
        return (XDP_PASS);

    data = (void *)(long)ctx->data;
    iphdr = data + sizeof(struct ethhdr);

    unsigned int src_ip = iphdr->saddr;
    bpf_trace_printk("SYN Packet Received from src IP: %u.%u.%u\n", 
        (src_ip) & 0xFF, 
        (src_ip >> 8) & 0xFF, 
        (src_ip >> 16) & 0xFF);

    if (tcphdr->syn)
    {
        bpf_trace_printk("SYN Packet Received!\\n");
        tmp = ip_list.lookup((unsigned long long *)&iphdr->saddr);
        if (tmp)
        {
            counter = *tmp;
            counter++;
            ip_list.update((unsigned long long *)&iphdr->saddr, &counter);
        }
        else
        {
            counter = 1;
            ip_list.update((unsigned long long *)&iphdr->saddr, &counter);
        }
        if (counter > 5)
        {
            bpf_trace_printk("SYN Packet Dropped!\\n");
            return (XDP_DROP);
        }
    }
    else if (tcphdr->ack)
    {
        tmp = ip_list.lookup((unsigned long long *)&iphdr->saddr);
        if (!tmp)
        {
            bpf_trace_printk("ACK Packet Dropped!\\n");
            return (XDP_PASS);
        }
        counter = *tmp;
        counter--;
        if (counter < 2)
            ip_list.delete((unsigned long long *)&iphdr->saddr);
        else
            ip_list.update((unsigned long long *)&iphdr->saddr, &counter);
    }

    return (XDP_PASS);
}
