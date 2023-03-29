#include "udp.h"


int udp_process(struct rte_mbuf *pstUdpMbuf) 
{
    struct rte_ipv4_hdr *pstIpHdr;
    struct rte_udp_hdr *pstUdpHdr;
    struct localhost *pstHost;
    struct offload *pstOffLoad;

    pstIpHdr = rte_pktmbuf_mtod_offset(pstUdpMbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
	pstUdpHdr = (struct rte_udp_hdr *)(pstIpHdr + 1);

    pstHost = get_hostinfo_fromip_port(pstIpHdr->dst_addr, pstUdpHdr->dst_port, pstIpHdr->next_proto_id);
    if (pstHost == NULL) 
    {
		rte_pktmbuf_free(pstUdpMbuf);
		return -3;
	} 
	
	struct in_addr addr;
	addr.s_addr = pstIpHdr->src_addr;
	printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(pstUdpHdr->src_port));

    pstOffLoad = rte_malloc("offload", sizeof(struct offload), 0);
	if (pstOffLoad == NULL) 
    {
		rte_pktmbuf_free(pstUdpMbuf);
		return -1;
	}

    pstOffLoad->dip = pstIpHdr->dst_addr;
	pstOffLoad->sip = pstIpHdr->src_addr;
	pstOffLoad->sport = pstUdpHdr->src_port;
	pstOffLoad->dport = pstUdpHdr->dst_port;
    pstOffLoad->protocol = IPPROTO_UDP;
	pstOffLoad->length = ntohs(pstUdpHdr->dgram_len);
    pstOffLoad->data = rte_malloc("unsigned char*", pstOffLoad->length - sizeof(struct rte_udp_hdr), 0);
	if (pstOffLoad->data == NULL) 
    {
		rte_pktmbuf_free(pstUdpMbuf);
		rte_free(pstOffLoad);
		return -2;
	}

    rte_memcpy(pstOffLoad->data, (unsigned char *)(pstUdpHdr+1), pstOffLoad->length - sizeof(struct rte_udp_hdr));

	rte_ring_mp_enqueue(pstHost->rcvbuf, pstOffLoad);  // recv buffer

	pthread_mutex_lock(&pstHost->mutex);
	pthread_cond_signal(&pstHost->cond);
	pthread_mutex_unlock(&pstHost->mutex);

	rte_pktmbuf_free(pstUdpMbuf);

    return 0;
}

static int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	unsigned char *data, uint16_t total_len) 
{
    struct rte_ether_hdr *pstEth;
    struct rte_ipv4_hdr *pstIp;
    struct rte_udp_hdr *pstUdp;

    // 1 ethhdr
	pstEth = (struct rte_ether_hdr *)msg;
	rte_memcpy(pstEth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(pstEth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	pstEth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2 iphdr 
	pstIp = (struct rte_ipv4_hdr *)(pstEth + 1);
	pstIp->version_ihl = 0x45;
	pstIp->type_of_service = 0;
	pstIp->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	pstIp->packet_id = 0;
	pstIp->fragment_offset = 0;
	pstIp->time_to_live = 64; // ttl = 64
	pstIp->next_proto_id = IPPROTO_UDP;
	pstIp->src_addr = sip;
	pstIp->dst_addr = dip;	
	pstIp->hdr_checksum = 0;
	pstIp->hdr_checksum = rte_ipv4_cksum(pstIp);

	// 3 udphdr 
	pstUdp = (struct rte_udp_hdr *)(pstIp + 1);
	pstUdp->src_port = sport;
	pstUdp->dst_port = dport;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	pstUdp->dgram_len = htons(udplen);
	rte_memcpy((uint8_t*)(pstUdp + 1), data, udplen);
	pstUdp->dgram_cksum = 0;
	pstUdp->dgram_cksum = rte_ipv4_udptcp_cksum(pstIp, pstUdp);

	return 0;
}

static struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, unsigned char *srcmac, unsigned char *dstmac,
	unsigned char *data, uint16_t length) 
{
    unsigned int uiTotalLen;
    struct rte_mbuf *pstMbuf;
    unsigned char *pucPktData;

    uiTotalLen = length + 42;   // 42 = eth + ip
    pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	
    pstMbuf->pkt_len = uiTotalLen;
    pstMbuf->data_len = uiTotalLen;
    pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char*);

	ng_encode_udp_apppkt(pucPktData, sip, dip, sport, dport, srcmac, dstmac,
		data, uiTotalLen);

	return pstMbuf;
}

int udp_out(struct rte_mempool *pstMbufPool) 
{
    struct localhost *pstHost;

    for(pstHost = g_pstHost; pstHost != NULL; pstHost = pstHost->next)
    {
        struct offload *pstOffLoad = NULL;
        int iSendCnt = rte_ring_mc_dequeue(pstHost->sndbuf, (void **)&pstOffLoad);
        if(iSendCnt < 0) 
            continue;
        
        struct in_addr addr;
		addr.s_addr = pstOffLoad->dip;
		printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(pstOffLoad->dport));

        unsigned char *dstmac = ng_get_dst_macaddr(pstOffLoad->dip); // 查询对端mac地址
		if (dstmac == NULL)  // 先广播发个arp包确定对端mac地址
        {
			struct rte_mbuf *pstArpbuf = ng_send_arp(pstMbufPool, RTE_ARP_OP_REQUEST, g_aucDefaultArpMac, 
				pstOffLoad->sip, pstOffLoad->dip);

			rte_ring_mp_enqueue_burst(g_pstRingIns->pstOutRing, (void **)&pstArpbuf, 1, NULL);

			rte_ring_mp_enqueue(pstHost->sndbuf, pstOffLoad); // 将取出的udp数据再次写入队列
		} 
        else 
        {
			struct rte_mbuf *pstUdpbuf = ng_udp_pkt(pstMbufPool, pstOffLoad->sip, pstOffLoad->dip, 
                    pstOffLoad->sport, pstOffLoad->dport, pstHost->localmac, 
                    dstmac, pstOffLoad->data, pstOffLoad->length);

			rte_ring_mp_enqueue_burst(g_pstRingIns->pstOutRing, (void **)&pstUdpbuf, 1, NULL);

			if (pstOffLoad->data != NULL)
				rte_free(pstOffLoad->data);
			
			rte_free(pstOffLoad);
		}
    }

    return 0;
}