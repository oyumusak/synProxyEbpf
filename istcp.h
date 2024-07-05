/*
	Omer Yumusak
*/

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

void *is_tcp(struct xdp_md *ctx)
{
	void			*data;
	void			*dataEnd;
	struct ethhdr	*eth;
	struct iphdr	*iph;
	struct tcphdr *tcph = 0;
	
	data = (void *)(long)ctx->data;
	dataEnd = (void *)(long)ctx->data_end;

	
	if (data + sizeof(struct ethhdr) > dataEnd)
		return (tcph);
	eth = (struct ethhdr *)data;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return (tcph);

	
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > dataEnd)
		return (tcph);
	iph = data + sizeof(struct ethhdr);

	if (iph->protocol != 6) //6 Tcp
		return (tcph);
	

	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > dataEnd)
		return ((void *)0);
	
	tcph = data + sizeof (struct ethhdr) + sizeof (struct iphdr);
	//tcph += sizeof(struct iphdr);

	return ((void *)tcph);
}