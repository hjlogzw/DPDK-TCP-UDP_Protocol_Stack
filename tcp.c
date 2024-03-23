#include "tcp.h"

static struct tcp_stream * tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{ 
    char acBuf[32] = {0};
    unsigned int uiSeed;
    struct tcp_stream *pstStream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
	if (pstStream == NULL) 
        return NULL;

<<<<<<< HEAD
	printf("tcp_stream_create!\n");

=======
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
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

static int tcp_handle_syn_rcvd(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr)
{
	if (pstTcphdr->tcp_flags & RTE_TCP_ACK_FLAG) 
	{
		if (pstStream->status == TCP_STATUS_SYN_RCVD) 
		{
			uint32_t acknum = ntohl(pstTcphdr->recv_ack);
			if (acknum == pstStream->snd_nxt + 1) 
			{
				printf("ack response success!\n");
			}
			else
			{
				printf("ack response error! \n");
			}

			pstStream->status = TCP_STATUS_ESTABLISHED;

			// accept
			struct tcp_stream *pstListener = tcp_stream_search(0, 0, 0, pstStream->dport);
			if (pstListener == NULL) 
			{
				rte_exit(EXIT_FAILURE, "tcp_stream_search failed\n");
			}

			pthread_mutex_lock(&pstListener->mutex);
			pthread_cond_signal(&pstListener->cond);   // 唤醒accept中的等待
			pthread_mutex_unlock(&pstListener->mutex);

#if ENABLE_SINGLE_EPOLL

<<<<<<< HEAD
			epoll_event_callback(g_pstTcpTbl->ep, pstListener->fd, EPOLLIN);
=======
			struct ng_tcp_table *table = tcpInstance();
			epoll_event_callback(table->ep, listener->fd, EPOLLIN);
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
#endif
		}
	}

	return 0;
}

static int ng_tcp_enqueue_recvbuffer(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int iTcplen) 
{
	struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstFragment == NULL) 
		return -1;

	memset(pstFragment, 0, sizeof(struct tcp_fragment));
	pstFragment->dport = ntohs(pstTcphdr->dst_port);
	pstFragment->sport = ntohs(pstTcphdr->src_port);

	// data_off：前4位表示包头到数据域起始位置之间的大小
	// 每一位表示4Byte，最大表示为 15*4Byte 大小
	uint8_t hdrlen = pstTcphdr->data_off >> 4;   
	int payloadlen = iTcplen - hdrlen * 4; // 数据域长度
<<<<<<< HEAD
	// if (pstTcphdr->tcp_flags & RTE_TCP_FIN_FLAG) 
	// 	printf("iTcplen = %d\n", iTcplen);
	// printf("payloadlen = %d\n", payloadlen);

=======
	if (pstTcphdr->tcp_flags & RTE_TCP_FIN_FLAG) 
		printf("iTcplen = %d\n", iTcplen);
	printf("payloadlen = %d\n", payloadlen);
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
	if(payloadlen > 0)
	{
		uint8_t *payload = (uint8_t*)pstTcphdr + hdrlen * 4;

		pstFragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
		if (pstFragment->data == NULL) 
		{
			rte_free(pstFragment);
			return -1;
		}

		memset(pstFragment->data, 0, payloadlen + 1);
		rte_memcpy(pstFragment->data, payload, payloadlen);
		pstFragment->length = payloadlen;
	}
	else if(payloadlen == 0)
	{
		pstFragment->length = 0;
		pstFragment->data = NULL;
	}

	rte_ring_mp_enqueue(pstStream->rcvbuf, pstFragment);

	pthread_mutex_lock(&pstStream->mutex);
	pthread_cond_signal(&pstStream->cond);
	pthread_mutex_unlock(&pstStream->mutex);

	return 0;
}

static int ng_tcp_send_ackpkt(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr) 
{
	struct tcp_fragment *pstAckFrag = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
	if (pstAckFrag == NULL) 
		return -1;
	
	memset(pstAckFrag, 0, sizeof(struct tcp_fragment));
	pstAckFrag->dport = pstTcphdr->src_port;
	pstAckFrag->sport = pstTcphdr->dst_port;

	// remote
	
<<<<<<< HEAD
	printf("tcp_send_ackpkt: %d, %d\n", ntohs(pstStream->rcv_nxt), ntohs(pstTcphdr->sent_seq));
=======
	printf("tcp_send_ackpkt: %d, %d\n", pstStream->rcv_nxt, ntohs(pstTcphdr->sent_seq));
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
	
	pstAckFrag->acknum = pstStream->rcv_nxt;
	pstAckFrag->seqnum = pstStream->snd_nxt;
	pstAckFrag->tcp_flags = RTE_TCP_ACK_FLAG;
	pstAckFrag->windows = D_TCP_INITIAL_WINDOW;
	pstAckFrag->hdrlen_off = 0x50;
	pstAckFrag->data = NULL;
	pstAckFrag->length = 0;
	
	rte_ring_mp_enqueue(pstStream->sndbuf, pstAckFrag);

	return 0;
}

static int tcp_handle_established(struct tcp_stream *pstStream, struct rte_tcp_hdr *pstTcphdr, int iTcplen) 
{
	if (pstTcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  // 异常：收到对端的SYN重传包
	{
<<<<<<< HEAD
		// printf("RTE_TCP_SYN_FLAG\n");
=======
		printf("RTE_TCP_SYN_FLAG\n");
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
	} 
	if(pstTcphdr->tcp_flags & RTE_TCP_PSH_FLAG)  // 收到对端的数据包，TCP数据域不为0
	{
		ng_tcp_enqueue_recvbuffer(pstStream, pstTcphdr, iTcplen);
		
#if ENABLE_SINGLE_EPOLL
<<<<<<< HEAD
		epoll_event_callback(g_pstTcpTbl->ep, pstStream->fd, EPOLLIN);
=======
		struct ng_tcp_table *table = tcpInstance();
		epoll_event_callback(table->ep, stream->fd, EPOLLIN);
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
#endif

		uint8_t hdrlen = pstTcphdr->data_off >> 4;
		int payloadlen = iTcplen - hdrlen * 4;
		
<<<<<<< HEAD
		pstStream->rcv_nxt = pstStream->rcv_nxt + payloadlen; // ntohl(pstStream->rcv_nxt + payloadlen);
=======
		pstStream->rcv_nxt = ntohl(pstStream->rcv_nxt + payloadlen);
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
		pstStream->snd_nxt = ntohl(pstTcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(pstStream, pstTcphdr);
	}
	if(pstTcphdr->tcp_flags & RTE_TCP_ACK_FLAG)  // 异常：收到对端的ACK重传包
	{
<<<<<<< HEAD
		// printf("RTE_TCP_ACK_FLAG\n");
=======
		printf("RTE_TCP_ACK_FLAG\n");
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
	}
	if (pstTcphdr->tcp_flags & RTE_TCP_FIN_FLAG)  // 对端关闭连接
	{
		printf("RTE_TCP_FIN_FLAG\n");
		pstStream->status = TCP_STATUS_CLOSE_WAIT;

<<<<<<< HEAD
		// 通知recv函数接收数据包
		ng_tcp_enqueue_recvbuffer(pstStream, pstTcphdr, pstTcphdr->data_off >> 4); 

#if ENABLE_SINGLE_EPOLL
		epoll_event_callback(g_pstTcpTbl->ep, pstStream->fd, EPOLLIN);
#endif
		// send ack ptk
		pstStream->rcv_nxt = pstStream->rcv_nxt + 1;// ntohl(pstStream->rcv_nxt + 1);
		pstStream->snd_nxt = ntohl(pstTcphdr->recv_ack);
		
		// 发送ACK响应至对端
		ng_tcp_send_ackpkt(pstStream, pstTcphdr); 
=======
		ng_tcp_enqueue_recvbuffer(pstStream, pstTcphdr, pstTcphdr->data_off >> 4);

#if ENABLE_SINGLE_EPOLL

		struct ng_tcp_table *table = tcpInstance();
		epoll_event_callback(table->ep, stream->fd, EPOLLIN);

#endif
		// send ack ptk
		pstStream->rcv_nxt = ntohl(pstStream->rcv_nxt + 1);
		pstStream->snd_nxt = ntohl(pstTcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(pstStream, pstTcphdr);
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
	}

	return 0;
}

static int tcp_handle_close_wait(struct tcp_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) 
	{ 
		if (stream->status == TCP_STATUS_CLOSE_WAIT) 
		{	

		}
	}
	
	return 0;
}

static int tcp_handle_last_ack(struct tcp_stream *stream, struct rte_tcp_hdr *tcphdr) 
{
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) 
	{
		if (stream->status == TCP_STATUS_LAST_ACK) 
		{
			stream->status = TCP_STATUS_CLOSED;
			printf("tcp_handle_last_ack\n");
			
			LL_REMOVE(stream, g_pstTcpTbl->tcb_set);

			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);

			rte_free(stream);
		}
	}

	return 0;
}

int tcp_process(struct rte_mbuf *pstTcpMbuf) 
{
    struct rte_ipv4_hdr *pstIpHdr;
    struct rte_tcp_hdr *pstTcpHdr;
    struct tcp_stream *pstTcpStream;
<<<<<<< HEAD
    unsigned short usOldTcpCkSum;	
=======
    unsigned short usOldTcpCkSum;
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
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

	// 搜索涵盖了半连接队列和全连接队列
	// 搜索的stream，根据status状态调用对应处理函数
    pstTcpStream = tcp_stream_search(pstIpHdr->src_addr, pstIpHdr->dst_addr, 
        pstTcpHdr->src_port, pstTcpHdr->dst_port);
    if (pstTcpStream == NULL) 
    { 
<<<<<<< HEAD
=======
        puts("no tcb create!");
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
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
			tcp_handle_syn_rcvd(pstTcpStream, pstTcpHdr);
			break;

		case TCP_STATUS_SYN_SENT: // client
			break;

		case TCP_STATUS_ESTABLISHED:  // server | client
		{ 
			int tcplen = ntohs(pstIpHdr->total_length) - sizeof(struct rte_ipv4_hdr);
			tcp_handle_established(pstTcpStream, pstTcpHdr, tcplen);
			printf("tcplen = %d\n", tcplen);
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
			tcp_handle_close_wait(pstTcpStream, pstTcpHdr);
			break;
			
		case TCP_STATUS_LAST_ACK:  // ~server
			tcp_handle_last_ack(pstTcpStream, pstTcpHdr);
			break;
    }

    return 0;
}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment, unsigned int total_len) 
{
	struct rte_ether_hdr *pstEth;
	struct rte_ipv4_hdr *pstIp;
	struct rte_tcp_hdr *pstTcp;

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
	pstIp->next_proto_id = IPPROTO_TCP;
	pstIp->src_addr = sip;
	pstIp->dst_addr = dip;
	pstIp->hdr_checksum = 0;
	pstIp->hdr_checksum = rte_ipv4_cksum(pstIp);

	// 3 tcphdr 
	pstTcp = (struct rte_tcp_hdr *)(pstIp + 1);
	pstTcp->src_port = fragment->sport;
	pstTcp->dst_port = fragment->dport;
	pstTcp->sent_seq = htonl(fragment->seqnum);
	pstTcp->recv_ack = htonl(fragment->acknum);
	pstTcp->data_off = fragment->hdrlen_off;
	pstTcp->rx_win = fragment->windows;
	pstTcp->tcp_urp = fragment->tcp_urp;
	pstTcp->tcp_flags = fragment->tcp_flags;
	if (fragment->data != NULL) 
	{
		uint8_t *payload = (uint8_t*)(pstTcp + 1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}
	pstTcp->cksum = 0;
	pstTcp->cksum = rte_ipv4_udptcp_cksum(pstIp, pstTcp);

	return 0;
}


static struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct tcp_fragment *fragment) 
{
	unsigned int uiTotalLen;
	struct rte_mbuf *pstMbuf;
    unsigned char *pucPktData;

	uiTotalLen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t) + fragment->length;  
	
	pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	
	pstMbuf->pkt_len = uiTotalLen;
    pstMbuf->data_len = uiTotalLen;
    pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char*);

	ng_encode_tcp_apppkt(pucPktData, sip, dip, srcmac, dstmac, fragment, uiTotalLen);

	return pstMbuf;
}

int tcp_out(struct rte_mempool *pstMbufPool) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_stream *pstStream = NULL;
<<<<<<< HEAD
	
=======

>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
	for(pstStream = pstTable->tcb_set; pstStream != NULL; pstStream = pstStream->next)
	{
		if(pstStream->sndbuf == NULL)
			continue;

		struct tcp_fragment *pstFragment = NULL;		
		int iSendCnt = rte_ring_mc_dequeue(pstStream->sndbuf, (void**)&pstFragment);
		if (iSendCnt < 0) 
			continue;

<<<<<<< HEAD
		// struct in_addr addr;
		// addr.s_addr = pstStream->sip;
		// printf("tcp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(pstFragment->dport));
=======
		struct in_addr addr;
		addr.s_addr = pstStream->sip;
		printf("tcp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(pstFragment->dport));
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f

		uint8_t *dstmac = ng_get_dst_macaddr(pstStream->sip); // 这里的源ip指的是对端ip
		if (dstmac == NULL)  // 先广播发个arp包确定对端mac地址 
		{
<<<<<<< HEAD
			printf("ng_send_arp\n");
=======
			//printf("ng_send_arp\n");
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
			struct rte_mbuf *pstArpbuf = ng_send_arp(pstMbufPool, RTE_ARP_OP_REQUEST, g_aucDefaultArpMac, 
				pstStream->dip, pstStream->sip);

			rte_ring_mp_enqueue_burst(g_pstRingIns->pstOutRing, (void **)&pstArpbuf, 1, NULL);

			rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);  // 将取出的数据再次放入队列
		} 
		else 
		{
<<<<<<< HEAD
			printf("ng_send_data\n");
=======
>>>>>>> c472b4b5fbedc52450a9bd050d196d2515ca995f
			struct rte_mbuf *pstTcpBuf = ng_tcp_pkt(pstMbufPool, pstStream->dip, pstStream->sip, 
												pstStream->localmac, dstmac, pstFragment);

			rte_ring_mp_enqueue_burst(g_pstRingIns->pstOutRing, (void **)&pstTcpBuf, 1, NULL);

			if (pstFragment->data != NULL)
				rte_free(pstFragment->data);
			
			rte_free(pstFragment);
		}
	}

    return 0;
}