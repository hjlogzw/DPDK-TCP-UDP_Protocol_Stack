#include "common.h"
#include "udp.h"
#include "tcp.h"


void dbg_print(char *info, unsigned char *dat, int dat_len)
{
    int i;

    printf("\n%s:%d\n", info, dat_len);
    for (i = 0; i < dat_len; i++)
    {
        if (i && (i % 16 == 0))
            printf("\n");
        printf("%02x ", dat[i]);
    }
    printf("\n");
}

struct tcp_table *tcpInstance(void) 
{
	if (g_pstTcpTbl == NULL) 
    {
		g_pstTcpTbl = rte_malloc("tcp_table", sizeof(struct tcp_table), 0);
		memset(g_pstTcpTbl, 0, sizeof(struct tcp_table));
	}
	return g_pstTcpTbl;
}

// todo:分割establish和listen为两个函数
struct tcp_stream * tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) 
{
	struct tcp_table *pstTable = tcpInstance();
	struct tcp_stream *iter = NULL;

	for (iter = pstTable->tcb_set; iter != NULL; iter = iter->next) { // established

		if (iter->sip == sip && iter->dip == dip && 
			    iter->sport == sport && iter->dport == dport) 
        {
			return iter;
		}

	}

	for (iter = pstTable->tcb_set; iter != NULL; iter = iter->next) 
    {
		if (iter->dport == dport && iter->status == TCP_STATUS_LISTEN)  // listen
        { 
			return iter;
		}
	}

	return NULL;
}

static struct tcp_stream *get_accept_tcb(uint16_t dport) 
{
	struct tcp_stream *apt;
	for (apt = g_pstTcpTbl->tcb_set; apt != NULL; apt = apt->next) 
    {
		if (dport == apt->dport && apt->fd == -1) 
        {
			return apt;
		}
	}

	return NULL;
}

static int get_fd_frombitmap(void) 
{
	int fd = D_DEFAULT_FD_NUM;
	for (; fd < D_MAX_FD_COUNT; fd ++) 
    {
		if ((g_ucFdTable[fd/8] & (0x1 << (fd % 8))) == 0) 
        {
			g_ucFdTable[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}

	return -1;
}

static int set_fd_frombitmap(int fd) 
{
	if (fd >= D_MAX_FD_COUNT) 
        return -1;

	g_ucFdTable[fd/8] &= ~(0x1 << (fd % 8));

	return 0;
}

struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, unsigned char proto) 
{
	struct localhost *pstHost = NULL;

	for (pstHost = g_pstHost; pstHost != NULL;pstHost = pstHost->next) 
    {
		if (dip == pstHost->localip && port == pstHost->localport && proto == pstHost->protocol) 
			return pstHost;
	}

	return NULL;
}

// todo: 改成三个接口
void* get_hostinfo_fromfd(int iSockFd) 
{
	struct localhost *pstHost = NULL;
	struct tcp_stream *pstStream = NULL;

	for (pstHost = g_pstHost; pstHost != NULL; pstHost = g_pstHost->next) 
    {
		if (iSockFd == pstHost->fd) 
			return pstHost;
	}

	for (pstStream = g_pstTcpTbl->tcb_set; pstStream != NULL; pstStream = pstStream->next) {
		if (iSockFd == pstStream->fd) {
			return pstStream;
		}
	}


#if ENABLE_SINGLE_EPOLL

	struct eventpoll *ep = table->ep;
	if (ep != NULL) {
		if (ep->fd == sockfd) {
			return ep;
		}
	}

#endif
	
	return NULL;
}

static struct arp_table *arp_table_instance(void) 
{
	if (g_pstArpTbl == NULL) 
    {
		g_pstArpTbl = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (g_pstArpTbl == NULL) 
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		
		memset(g_pstArpTbl, 0, sizeof(struct arp_table));

		pthread_spin_init(&g_pstArpTbl->spinlock, PTHREAD_PROCESS_SHARED);
	}

	return g_pstArpTbl;
}

unsigned char* ng_get_dst_macaddr(uint32_t dip) 
{
	struct arp_entry *pstIter;
	struct arp_table *pstTbl = arp_table_instance();

	int count = pstTbl->count;
	
	for (pstIter = pstTbl->entries; count-- != 0 && pstIter != NULL; pstIter = pstIter->next) 
    {
		if (dip == pstIter->ip) 
			return pstIter->hwaddr;
	}

	return NULL;
}

int ng_arp_entry_insert(uint32_t ip, unsigned char *mac)
{
    struct arp_table *pstTbl = arp_table_instance();
    struct arp_entry *pstEntry = NULL;
    unsigned char *pstHwaddr = NULL;

    pstHwaddr = ng_get_dst_macaddr(ip);
    if(pstHwaddr == NULL)
    {
        pstEntry = rte_malloc("arp_entry", sizeof(struct arp_entry), 0);
		if (pstEntry) 
        {
			memset(pstEntry, 0, sizeof(struct arp_entry));

			pstEntry->ip = ip;
			rte_memcpy(pstEntry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
			pstEntry->type = 0;

			pthread_spin_lock(&pstTbl->spinlock);
			LL_ADD(pstEntry, pstTbl->entries);
			pstTbl->count ++;
			pthread_spin_unlock(&pstTbl->spinlock);
		}
        return 1;
    }

    return 0;
}

static int ng_encode_arp_pkt(unsigned char *msg, uint16_t opcode, unsigned char *dst_mac, 
    uint32_t sip, uint32_t dip) 
{
    struct rte_ether_hdr *pstEth = NULL;
    struct rte_arp_hdr *pstArp = NULL;
    unsigned char aucMac[RTE_ETHER_ADDR_LEN] = {0x0};

    // eth
    pstEth = (struct rte_ether_hdr*)msg;
    rte_memcpy(pstEth->s_addr.addr_bytes, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
    if (!strncmp((const char *)dst_mac, (const char *)g_aucDefaultArpMac, RTE_ETHER_ADDR_LEN)) 
    {
		rte_memcpy(pstEth->d_addr.addr_bytes, aucMac, RTE_ETHER_ADDR_LEN);
	} 
    else
    {
		rte_memcpy(pstEth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
    pstEth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // arp
    pstArp = (struct rte_arp_hdr *)(pstEth + 1);
    pstArp->arp_hardware = htons(1);                    // 硬件类型：1 以太网
    pstArp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);  // 协议类型：0x0800 IP地址
    pstArp->arp_hlen = RTE_ETHER_ADDR_LEN;              // 硬件地址长度：6
    pstArp->arp_plen = sizeof(uint32_t);                // 协议地址长度：4
    pstArp->arp_opcode = htons(opcode);                 // OP

    rte_memcpy(pstArp->arp_data.arp_sha.addr_bytes, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(pstArp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	pstArp->arp_data.arp_sip = sip;
	pstArp->arp_data.arp_tip = dip;
	
	return 0;
}

struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, unsigned char *dst_mac, 
                                uint32_t sip, uint32_t dip) 
{
	const unsigned int uiTotalLen = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
    unsigned char *pucPktData;

	struct rte_mbuf *pstMbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!pstMbuf) 
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");

	pstMbuf->pkt_len = uiTotalLen;
	pstMbuf->data_len = uiTotalLen;

	pucPktData = rte_pktmbuf_mtod(pstMbuf, unsigned char *);
	ng_encode_arp_pkt(pucPktData, opcode, dst_mac, sip, dip);

	return pstMbuf;
}

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol)
{
    int iFd;
    struct localhost *pstHost;
    pthread_cond_t pctCond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t pmtMutex = PTHREAD_MUTEX_INITIALIZER;

    iFd = get_fd_frombitmap();
    if(type == SOCK_DGRAM) // udp
    {
        pstHost = rte_malloc("localhost", sizeof(struct localhost), 0);
        if(pstHost == NULL)
        {
            printf("[%s][%d]: rte_malloc fail!\n", __FUNCTION__, __LINE__);
            return -1;
        }

        memset(pstHost, 0x00, sizeof(struct localhost));
        pstHost->fd = iFd;
        pstHost->protocol = IPPROTO_UDP;
        pstHost->rcvbuf = rte_ring_create("recv buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (pstHost->rcvbuf == NULL) 
        {
            printf("[%s][%d]: rte_ring_create fail!\n", __FUNCTION__, __LINE__);
			rte_free(pstHost);
			return -1;
		}
        pstHost->sndbuf = rte_ring_create("send buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (pstHost->sndbuf == NULL) 
        {
            printf("[%s][%d]: rte_ring_create fail!\n", __FUNCTION__, __LINE__);
            rte_ring_free(pstHost->rcvbuf);
			rte_free(pstHost);
			return -1;
		}

		rte_memcpy(&pstHost->cond, &pctCond, sizeof(pthread_cond_t));

		rte_memcpy(&pstHost->mutex, &pmtMutex, sizeof(pthread_mutex_t));

		LL_ADD(pstHost, g_pstHost);
    }
    else if(type == SOCK_STREAM) // tcp
    {
        struct tcp_stream *pstStream = rte_malloc("tcp_stream", sizeof(struct tcp_stream), 0);
		if (pstStream == NULL) 
			return -1;
		
		memset(pstStream, 0, sizeof(struct tcp_stream));
        pstStream->fd = iFd;
        pstStream->protocol = IPPROTO_TCP;
		pstStream->next = pstStream->prev = NULL;

        pstStream->rcvbuf = rte_ring_create("tcp recv buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (pstStream->rcvbuf == NULL) 
        {
			rte_free(pstStream);
			return -1;
		}
		pstStream->sndbuf = rte_ring_create("tcp send buffer", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (pstStream->sndbuf == NULL) 
        {
			rte_ring_free(pstStream->rcvbuf);
			rte_free(pstStream);
			return -1;
		}

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&pstStream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&pstStream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        g_pstTcpTbl = tcpInstance();
		LL_ADD(pstStream, g_pstTcpTbl->tcb_set);           // todo :hash
    }

    return iFd;
}

int nbind(int sockfd, const struct sockaddr *addr, __attribute__((unused))  socklen_t addrlen)
{
    void *info = NULL;

    info = get_hostinfo_fromfd(sockfd);
    if(info == NULL) 
        return -1;

    struct localhost *pstHostInfo = (struct localhost *)info;
    if(pstHostInfo->protocol == IPPROTO_UDP)
    {
        const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)addr;
		pstHostInfo->localport = pstAddr->sin_port;
		rte_memcpy(&pstHostInfo->localip, &pstAddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(pstHostInfo->localmac, &g_stCpuMac, RTE_ETHER_ADDR_LEN);
    }
    else if(pstHostInfo->protocol == IPPROTO_TCP)
    {
        struct tcp_stream* pstStream = (struct tcp_stream*)pstHostInfo;

        const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)addr;
		pstStream->dport = pstAddr->sin_port;
		rte_memcpy(&pstStream->dip, &pstAddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(pstStream->localmac, &g_stCpuMac, RTE_ETHER_ADDR_LEN);

		pstStream->status = TCP_STATUS_CLOSED;
    }

    return 0;
}

int nlisten(int sockfd, __attribute__((unused)) int backlog)
{
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
	if (pstStream->protocol == IPPROTO_TCP) 
    {
		pstStream->status = TCP_STATUS_LISTEN;
	}

    return 0;
}

int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen)
{
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if (pstStream->protocol == IPPROTO_TCP) 
    {
        struct tcp_stream *pstAccept = NULL;

        pthread_mutex_lock(&pstStream->mutex);
        while((pstAccept = get_accept_tcb(pstStream->dport)) == NULL)
        {
            pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
        }
        pthread_mutex_unlock(&pstStream->mutex);

        pstAccept->fd = get_fd_frombitmap();

        struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = pstAccept->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &pstAccept->sip, sizeof(uint32_t));

		return pstAccept->fd;
    }

    return -1;
}

ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags)
{
    unsigned int uiLength = 0;
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if(pstStream->protocol == IPPROTO_TCP)
    {
        struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
		if (pstFragment == NULL) 
        {
			return -2;
		}

		memset(pstFragment, 0, sizeof(struct tcp_fragment));
        pstFragment->dport = pstStream->sport;
		pstFragment->sport = pstStream->dport;
		pstFragment->acknum = pstStream->rcv_nxt;
		pstFragment->seqnum = pstStream->snd_nxt;
		pstFragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		pstFragment->windows = D_TCP_INITIAL_WINDOW;
		pstFragment->hdrlen_off = 0x50;

        pstFragment->data = rte_malloc("unsigned char *", len + 1, 0);
		if (pstFragment->data == NULL) 
        {
			rte_free(pstFragment);
			return -1;
		}
		memset(pstFragment->data, 0, len+1);

		rte_memcpy(pstFragment->data, buf, len);
		pstFragment->length = len;
		uiLength = pstFragment->length;

		rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
    }

    return uiLength;
}

ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags)
{
    ssize_t length = 0;
    void *pstHostInfo = get_hostinfo_fromfd(sockfd);
	if (pstHostInfo == NULL) 
        return -1;

	struct tcp_stream *pstStream = (struct tcp_stream *)pstHostInfo;
    if(pstStream->protocol == IPPROTO_TCP)
    {
        struct tcp_fragment *pstFragment = NULL;
        int iRcvNum = 0;

        // 等待接收队列中的数据到来
        pthread_mutex_lock(&pstStream->mutex);
		while ((iRcvNum = rte_ring_mc_dequeue(pstStream->rcvbuf, (void **)&pstFragment)) < 0) 
        {
			pthread_cond_wait(&pstStream->cond, &pstStream->mutex);
		}
		pthread_mutex_unlock(&pstStream->mutex);

        if (pstFragment->length > len) 
        {
            rte_memcpy(buf, pstFragment->data, len);

			uint32_t i = 0;
			for(i = 0; i < pstFragment->length - len; i ++) 
            {
				pstFragment->data[i] = pstFragment->data[len + i];
			}
			pstFragment->length = pstFragment->length - len;
			length = pstFragment->length;

			rte_ring_mp_enqueue(pstStream->rcvbuf, pstFragment);
        }
        else if(pstFragment->length == 0)
        {
            rte_free(pstFragment);
			return 0;
        }
        else
        {
            rte_memcpy(buf, pstFragment->data, pstFragment->length);
			length = pstFragment->length;

			rte_free(pstFragment->data);
			pstFragment->data = NULL;

			rte_free(pstFragment);
        }
    }

    return length;
}

ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen)
{
    struct localhost *pstHostInfo = NULL;
    struct offload *pstOffLoad = NULL;
    struct sockaddr_in *pstAddr = NULL;
	unsigned char *pucPtr = NULL;
    int iLen = 0;
    int iRet = -1;

    pstHostInfo = (struct localhost *)get_hostinfo_fromfd(sockfd);
    if(pstHostInfo == NULL) 
        return -1;
    
    pthread_mutex_lock(&pstHostInfo->mutex);
    while((iRet = rte_ring_mc_dequeue(pstHostInfo->rcvbuf, (void**)&pstOffLoad)) < 0)
    {
        pthread_cond_wait(&pstHostInfo->cond, &pstHostInfo->mutex);
    }
    pthread_mutex_unlock(&pstHostInfo->mutex);

    pstAddr = (struct sockaddr_in *)src_addr;
    pstAddr->sin_port = pstOffLoad->sport;
    rte_memcpy(&pstAddr->sin_addr.s_addr, &pstOffLoad->sip, sizeof(uint32_t));

    if(len < pstOffLoad->length)
    {
        rte_memcpy(buf, pstOffLoad->data, len);

        pucPtr = rte_malloc("unsigned char *", pstOffLoad->length - len, 0);
		rte_memcpy(pucPtr, pstOffLoad->data + len, pstOffLoad->length - len);

		pstOffLoad->length -= len;
		rte_free(pstOffLoad->data);
		pstOffLoad->data = pucPtr;
		
		rte_ring_mp_enqueue(pstHostInfo->rcvbuf, pstOffLoad);

		return len;
    }

    iLen = pstOffLoad->length;
    rte_memcpy(buf, pstOffLoad->data, pstOffLoad->length);
    
    rte_free(pstOffLoad->data);
    rte_free(pstOffLoad);
    
    return iLen;
}   

ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen)
{
    struct localhost *pstHostInfo = NULL;
    struct offload *pstOffLoad = NULL;
    const struct sockaddr_in *pstAddr = (const struct sockaddr_in *)dest_addr;

    pstHostInfo = (struct localhost *)get_hostinfo_fromfd(sockfd);
    if(pstHostInfo == NULL) 
        return -1;

    pstOffLoad = rte_malloc("offload", sizeof(struct offload), 0);
	if (pstOffLoad == NULL) 
        return -1;

    pstOffLoad->dip = pstAddr->sin_addr.s_addr;
	pstOffLoad->dport = pstAddr->sin_port;
	pstOffLoad->sip = pstHostInfo->localip;
	pstOffLoad->sport = pstHostInfo->localport;
	pstOffLoad->length = len;

    
    struct in_addr addr;
	addr.s_addr = pstOffLoad->dip;
	printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(pstOffLoad->dport));
    
    
    pstOffLoad->data = rte_malloc("unsigned char *", len, 0);
	if (pstOffLoad->data == NULL) {
		rte_free(pstOffLoad);
		return -1;
	}

	rte_memcpy(pstOffLoad->data, buf, len);

	rte_ring_mp_enqueue(pstHostInfo->sndbuf, pstOffLoad);

	return len;
}

int nclose(int fd)
{
    void *info = NULL;

    info = (struct localhost *)get_hostinfo_fromfd(fd);
    if(info == NULL) 
        return -1;

    struct localhost *pstHostInfo = (struct localhost *)info;
    if(pstHostInfo->protocol == IPPROTO_UDP)
    {
        LL_REMOVE(pstHostInfo, g_pstHost);

        if (pstHostInfo->rcvbuf)
			rte_ring_free(pstHostInfo->rcvbuf);
		if (pstHostInfo->sndbuf) 
			rte_ring_free(pstHostInfo->sndbuf);

		rte_free(pstHostInfo);

		set_fd_frombitmap(fd);
    }
    else if(pstHostInfo->protocol == IPPROTO_TCP)
    {
        struct tcp_stream *pstStream = (struct tcp_stream*)info;
        if (pstStream->status != TCP_STATUS_LISTEN)
        {
            struct tcp_fragment *pstFragment = rte_malloc("tcp_fragment", sizeof(struct tcp_fragment), 0);
			if (pstFragment == NULL) 
                return -1;

            memset(pstFragment, 0x00, sizeof(struct tcp_fragment));
            pstFragment->data = NULL;
			pstFragment->length = 0;
			pstFragment->sport = pstStream->dport;
			pstFragment->dport = pstStream->sport;

			pstFragment->seqnum = pstStream->snd_nxt;
			pstFragment->acknum = pstStream->rcv_nxt;

			pstFragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;  // 发送FIN
			pstFragment->windows = D_TCP_INITIAL_WINDOW;
			pstFragment->hdrlen_off = 0x50;

            rte_ring_mp_enqueue(pstStream->sndbuf, pstFragment);
			pstStream->status = TCP_STATUS_LAST_ACK;

            set_fd_frombitmap(fd); 
        }
        else
        {
            LL_REMOVE(pstStream, g_pstTcpTbl->tcb_set);	
			rte_free(pstStream);
        }
    }

    return 0;
}
