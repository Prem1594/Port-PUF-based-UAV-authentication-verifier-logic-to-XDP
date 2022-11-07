#include <stddef.h>
#include <stdbool.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/swab.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdint.h>
#include <bpf/bpf_endian.h>
//#include "common.h"
#define RET 0

#ifdef DEBUG
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})
#endif

#define PIN_GLOBAL_NS       2


struct auth_header{
	uint8_t msgType;
	uint32_t challenge;
}__attribute__((packed, aligned(1)));


SEC("ingress")
int parse_ingress(struct xdp_md *ctx)
{
   void *data = (void *)(long)ctx->data;
   void *data_end = (void *)(long)ctx->data_end;
    
    // structures for parsing appropriate headers
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    
    // boundary checks must , else the verifier rejects the program.
    if(data < data_end)
    {
        eth = data;
        if (data + sizeof(*eth) > data_end)
            return XDP_DROP;
	
        if (bpf_htons(eth->h_proto) != 0x0800) {
            bpf_printk("Received non IP packet with eth thype = %x", bpf_htons(eth->h_proto));
            return XDP_PASS;
        }

	// it is an IP packet (till here)
        iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return XDP_DROP;

        // TCP
        if (iph->protocol == 0x6) 
        {
            //struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
            tcph = data + sizeof(*eth) + sizeof(*iph);
            if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
                return XDP_DROP;

        }
        else if (iph->protocol == 0x11) //UDP
        {
           //struct udphdr *udph = data + sizeof(*eth) + sizeof(*iph);
           udph = data + sizeof(*eth) + sizeof(*iph);
           if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) > data_end)
               return XDP_DROP;
           //bpf_printk("Received UDP pkt with l4_sport=%d, l4_dport=%d", bpf_htons(udph->source), bpf_htons(udph->dest));
           char mine2[] = "Received UDP packet!";
           bpf_trace_printk(mine2,sizeof(mine2));
           bpf_printk("Recieved UDP packet");
          // bpf_trace_printk(fmt, sizeof(fmt));
          
          
          //getting the udp payload
          unsigned long payload_size;
          payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
          
          struct auth_header *payload = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph);
          if(data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) +sizeof(*payload) > data_end){
            	char mine3[] = "unauthorized buffer access\n";
            	bpf_trace_printk(mine3,sizeof(mine3));	
            	return XDP_DROP;
          }

	// boundary check for payload             
	if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) + sizeof(*payload) > data_end){
            	return XDP_DROP;
        }
        uint8_t msg_type = payload->msgType;

	bpf_printk("received msg type values is %d ",msg_type);
	
	if(msg_type == 0)
	{
		bpf_printk("Yes msg_type is 0, this is a auth request message");
		// checking
		return XDP_PASS;
	}
            
        }
        else if (iph->protocol == 0x01)
        {
            char mine[] = "Received ICMP packet!";
            bpf_trace_printk(mine,sizeof(mine));          
            
        }

        return RET;
    }
   
    	//return XDP_PASS;
	return RET;
}
char _license[] SEC("license") = "GPL";
