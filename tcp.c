#include "tcp.h"

static struct tcp_stream * tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{ 
    char acBuf[32] = {0};
    unsigned int uiSeed;
    struct tcp_stream *pstStream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
	if (pstStream == NULL) 
        return NULL;

    pstStream->sip = sip;
    pstStream->dip = dip;
    pstStream->sport = sport;
    pstStream->dport = dport;
    pstStream->protocol = IPPROTO_TCP;
    pstStream->fd = -1;
    pstStream->status = TCP_STATUS_LISTEN;

    sprintf(acBuf, "sndbuf%x%d", sip, sport);
	pstStream->sndbuf = rte_ring_create(acBuf, D_RING_SIZE, rte_socket_id(), 0);
	sprintf(acBuf, "rcvbuf%x%d", sip, sport);
	pstStream->rcvbuf = rte_ring_create(acBuf, D_RING_SIZE, rte_socket_id(), 0);

    // seq num
	uiSeed = time(NULL);
	pstStream->snd_nxt = rand_r(&uiSeed) % D_TCP_MAX_SEQ;
	rte_memcpy(pstStream->localmac, &g_stCpuMac, RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&pstStream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&pstStream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    return pstStream;
}

static int tcp_handle_listen(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, 
                                struct rte_ipv4_hdr *pstIphdr) 
{
    if (pstTcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  
    {
        if (pstStream->status == TCP_STATUS_LISTEN)
        {
            struct tcp_stream *pstSyn = tcp_stream_create(pstIphdr->src_addr, pstIphdr->dst_addr, 
                                                            pstTcphdr->src_port, pstTcphdr->dst_port);
			LL_ADD(pstSyn, g_pstTcpTbl->tcb_set);

            struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
			if (pstFragment == NULL) 
                return -1;
			memset(pstFragment, 0, sizeof(struct tcp_fragment));

            pstFragment->sport = pstTcphdr->dst_port;
			pstFragment->dport = pstTcphdr->src_port;

            struct in_addr addr;
			addr.s_addr = pstSyn->sip;
			printf("tcp ---> src: %s:%d ", inet_ntoa(addr), ntohs(pstTcphdr->src_port));

			addr.s_addr = pstSyn->dip;
			printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(pstTcphdr->dst_port));

            pstFragment->seqnum = pstSyn->snd_nxt;
			pstFragment->acknum = ntohl(pstTcphdr->sent_seq) + 1;
			pstSyn->rcv_nxt = pstFragment->acknum;
			
			pstFragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			pstFragment->windows = D_TCP_INITIAL_WINDOW;
			pstFragment->hdrlen_off = 0x50;
			
			pstFragment->data = NULL;
			pstFragment->length = 0;

			rte_ring_mp_enqueue(pstSyn->sndbuf, pstFragment);
			
			pstSyn->status = TCP_STATUS_SYN_RCVD;
        }
    }

    return 0;
}

int tcp_process(struct rte_mbuf *pstTcpMbuf) 
{
    struct rte_ipv4_hdr *pstIpHdr;
    struct rte_tcp_hdr *pstTcpHdr;
    struct tcp_stream *pstTcpStream;
    unsigned short usOldTcpCkSum;
    unsigned short usNewTcpCkSum;

    pstIpHdr = rte_pktmbuf_mtod_offset(pstTcpMbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    pstTcpHdr = (struct rte_tcp_hdr *)(pstIpHdr + 1);

    // 校验和
    usOldTcpCkSum = pstTcpHdr->cksum;
    pstTcpHdr->cksum = 0;
    usNewTcpCkSum = rte_ipv4_udptcp_cksum(pstIpHdr, pstTcpHdr);
    if (usOldTcpCkSum != usNewTcpCkSum) 
    { 
		printf("cksum: %x, tcp cksum: %x\n", usOldTcpCkSum, usNewTcpCkSum);
		rte_pktmbuf_free(pstTcpMbuf);
		return -1;
	}

    pstTcpStream = tcp_stream_search(pstIpHdr->src_addr, pstIpHdr->dst_addr, 
        pstTcpHdr->src_port, pstTcpHdr->dst_port);
    if (pstTcpStream == NULL) 
    { 
        puts("no tcb create!");
		rte_pktmbuf_free(pstTcpMbuf);
		return -2;
	}

    switch(pstTcpStream->status)
    {
        case TCP_STATUS_CLOSED: //client 
			break;
			
		case TCP_STATUS_LISTEN: // server
			tcp_handle_listen(pstTcpStream, pstTcpHdr, pstIpHdr);
			break;

		case TCP_STATUS_SYN_RCVD: // server
			// tcp_handle_syn_rcvd(stream, tcphdr);
			break;

		case TCP_STATUS_SYN_SENT: // client
			break;

		case TCP_STATUS_ESTABLISHED: { // server | client

			// int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
			
			// tcp_handle_established(stream, tcphdr, tcplen);
			
			break;
		}
		case TCP_STATUS_FIN_WAIT_1: //  ~client
			break;
			
		case TCP_STATUS_FIN_WAIT_2: // ~client
			break;
			
		case TCP_STATUS_CLOSING: // ~client
			break;
			
		case TCP_STATUS_TIME_WAIT: // ~client
			break;

		case TCP_STATUS_CLOSE_WAIT: // ~server
			// tcp_handle_close_wait(stream, tcphdr);
			break;
			
		case TCP_STATUS_LAST_ACK:  // ~server
			// tcp_handle_last_ack(stream, tcphdr);
			break;
    }

    return 0;
}


int tcp_out(struct rte_mempool *pstMbufPool) 
{

    return 0;
}