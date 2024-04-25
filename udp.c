#include "dpdk_common.h"

int udp_process(struct rte_mbuf *udpMbuf){

    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpMbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr*)(iphdr + 1);

    // test
    print_addr(iphdr->src_addr, ntohs(udphdr->src_port));
    
    

    return 0;
}
