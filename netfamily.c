#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>

#include "common.h"
#include "tcp.h"
#include "udp.h"

struct rte_ether_addr g_stCpuMac;
struct rte_kni *g_pstKni;                    // todo：后续将全局变量统一初始化，不再使用getInstance()
struct St_InOut_Ring *g_pstRingIns = NULL;   // todo：后续将全局变量统一初始化，不再使用getInstance()
struct localhost *g_pstHost = NULL;          // todo：后续将全局变量统一初始化，不再使用getInstance()
struct arp_table *g_pstArpTbl = NULL;        // todo：后续将全局变量统一初始化，不再使用getInstance()
struct tcp_table *g_pstTcpTbl = NULL;		 // todo：后续将全局变量统一初始化，不再使用getInstance()

unsigned char g_aucDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

unsigned char g_ucFdTable[D_MAX_FD_COUNT] = {0};

static struct St_InOut_Ring *ringInstance(void) 
{
	if (g_pstRingIns == NULL) 
    {
		g_pstRingIns = rte_malloc("in/out ring", sizeof(struct St_InOut_Ring), 0);
		memset(g_pstRingIns, 0, sizeof(struct St_InOut_Ring));
	}

	return g_pstRingIns;
}

void ng_init_port(struct rte_mempool *pstMbufPoolPub)
{
    unsigned int uiPortsNum;
    const int iRxQueueNum = 1;
	const int iTxQueueNum = 1;
    int iRet;
    struct rte_eth_dev_info stDevInfo;
    struct rte_eth_txconf stTxConf;
    struct rte_eth_conf stPortConf =    // 端口配置信息
    {
        .rxmode = {.max_rx_pkt_len = 1518 }   // RTE_ETHER_MAX_LEN = 1518
    };
    
    uiPortsNum = rte_eth_dev_count_avail(); 
	if (uiPortsNum == 0) 
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");

	rte_eth_dev_info_get(D_PORT_ID, &stDevInfo); 
	
    // 配置以太网设备
	rte_eth_dev_configure(D_PORT_ID, iRxQueueNum, iTxQueueNum, &stPortConf);

    iRet = rte_eth_rx_queue_setup(D_PORT_ID, 0 , 1024, rte_eth_dev_socket_id(D_PORT_ID), NULL, pstMbufPoolPub);
	if(iRet < 0) 
	    rte_exit(EXIT_FAILURE, "Could not setup RX queue!\n");

	stTxConf = stDevInfo.default_txconf;
	stTxConf.offloads = stPortConf.txmode.offloads;
    iRet = rte_eth_tx_queue_setup(D_PORT_ID, 0 , 1024, rte_eth_dev_socket_id(D_PORT_ID), &stTxConf);
	if (iRet < 0) 
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");

	if (rte_eth_dev_start(D_PORT_ID) < 0 )
		rte_exit(EXIT_FAILURE, "Could not start\n");
    
    rte_eth_promiscuous_enable(D_PORT_ID);
}

static int ng_config_network_if(uint16_t port_id, unsigned char if_up) {

	if (!rte_eth_dev_is_valid_port(port_id)) {
		return -EINVAL;
	}

	int ret = 0;
	if (if_up) {

		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);

	} else {

		rte_eth_dev_stop(port_id);

	}

	if (ret < 0) {
		printf("Failed to start port : %d\n", port_id);
	}

	return 0;
}

static struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool) {

	struct rte_kni *kni_hanlder = NULL;
	
	struct rte_kni_conf conf;
	memset(&conf, 0, sizeof(conf));

	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", D_PORT_ID);
	conf.group_id = D_PORT_ID;
	conf.mbuf_size = D_MAX_PACKET_SIZE;
	rte_eth_macaddr_get(D_PORT_ID, (struct rte_ether_addr *)conf.mac_addr);
	rte_eth_dev_get_mtu(D_PORT_ID, &conf.mtu);

	// print_ethaddr("ng_alloc_kni: ", (struct ether_addr *)conf.mac_addr);

/*
	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(D_PORT_ID, &dev_info);
	*/


	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));

	ops.port_id = D_PORT_ID;
	ops.config_network_if = ng_config_network_if;
	

	kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);	
	if (!kni_hanlder) {
		rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", D_PORT_ID);
	}
	
	return kni_hanlder;
}

static int pkt_process(void *arg)
{
    struct rte_mempool *pstMbufPool;
    int iRxNum;
	int i;
	struct rte_mbuf *pstMbuf[32];
	struct rte_ether_hdr *pstEthHdr;
	// struct arp_hdr *pstArpHdr;
    struct rte_ipv4_hdr *pstIpHdr;

    pstMbufPool = (struct rte_mempool *)arg;
    while(1)
    {
        iRxNum = rte_ring_mc_dequeue_burst(g_pstRingIns->pstInRing, (void**)pstMbuf, D_BURST_SIZE, NULL);
        
        if(iRxNum <= 0)
			continue;
        
        for(i = 0; i < iRxNum; ++i)
        {
            pstEthHdr = rte_pktmbuf_mtod_offset(pstMbuf[i], struct rte_ether_hdr *, 0);
            dbg_print("pstEthHdr->ether_type", (unsigned char*)&pstEthHdr->ether_type, sizeof(uint16_t));
            if (pstEthHdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))   //IPv4: 0800 
            {
                pstIpHdr = (struct rte_ipv4_hdr *)(pstEthHdr + 1);
                dbg_print("pstIpHdr->next_proto_id", (unsigned char*)&pstIpHdr->next_proto_id, sizeof(unsigned char));
                
				// 维护一个arp表
				ng_arp_entry_insert(pstIpHdr->src_addr, pstEthHdr->s_addr.addr_bytes);
                if(pstIpHdr->next_proto_id == IPPROTO_UDP) // udp 
                {
                    // udp process
                    udp_process(pstMbuf[i]);
                }
                else if(pstIpHdr->next_proto_id == IPPROTO_TCP)  // tcp
                {
                    printf("tcp_process ---\n");
					tcp_process(pstMbuf[i]);
                }
            }   
        }

        // rte_kni_handle_request(g_pstKni);
        // to send
        udp_out(pstMbufPool);
        // tcp_out(pstMbufPool);
    }
    return 0;
}

int udp_server_entry(__attribute__((unused))  void *arg) 
{           
    int iConnfd;
	struct sockaddr_in stLocalAddr, stClientAddr; 
	socklen_t uiAddrLen = sizeof(stClientAddr);;
	char acBuf[D_UDP_BUFFER_SIZE] = {0};

	iConnfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (iConnfd == -1) 
	{
		printf("nsocket failed\n");
		return -1;
	} 

	memset(&stLocalAddr, 0, sizeof(struct sockaddr_in));

	stLocalAddr.sin_port = htons(8889);
	stLocalAddr.sin_family = AF_INET;
	stLocalAddr.sin_addr.s_addr = inet_addr("192.168.1.106"); 
	
	nbind(iConnfd, (struct sockaddr*)&stLocalAddr, sizeof(stLocalAddr));

	while (1) {

		if (nrecvfrom(iConnfd, acBuf, D_UDP_BUFFER_SIZE, 0, 
			(struct sockaddr*)&stClientAddr, &uiAddrLen) < 0) {

			continue;

		} else {

			printf("recv from %s:%d, data:%s\n", inet_ntoa(stClientAddr.sin_addr), 
				ntohs(stClientAddr.sin_port), acBuf);
			nsendto(iConnfd, acBuf, strlen(acBuf), 0, 
				(struct sockaddr*)&stClientAddr, sizeof(stClientAddr));
		}

	}

	nclose(iConnfd);

    return 0;
}

int tcp_server_entry(__attribute__((unused))  void *arg)  
{
	int listenfd;
	int iRet = -1;
	struct sockaddr_in servaddr;
	
	listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) 
	{
		printf("[%s][%d] nsocket error!\n", __FUNCTION__, __LINE__);
		return -1;
	}

	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	iRet = nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if(iRet < 0)
	{
		printf("nbind error!\n");
		return -1;
	}

	nlisten(listenfd, 10);

	while (1) 
	{
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

		char buff[D_TCP_BUFFER_SIZE] = {0};
		while (1) 
		{
			int n = nrecv(connfd, buff, D_TCP_BUFFER_SIZE, 0); //block
			if (n > 0) 
			{
				printf("recv: %s\n", buff);
				nsend(connfd, buff, n, 0);
			} 
			else if (n == 0) 
			{
				nclose(connfd);
				break;
			} 
			else 
			{ //nonblock

			}
		}

	}
	nclose(listenfd);

    return 0;
}

int main(int argc, char *argv[]) 
{
    struct rte_mempool *pstMbufPoolPub;
    struct St_InOut_Ring *pstRing;
    struct rte_mbuf *pstRecvMbuf[32] = {NULL};
    struct rte_mbuf *pstSendMbuf[32] = {NULL};
    int iRxNum;
    int iTotalNum;
    int iOffset;
    int iTxNum;

    unsigned int uiCoreId;

    if(rte_eal_init(argc, argv) < 0)
	    rte_exit(EXIT_FAILURE, "Error with EAL init\n");	

    pstMbufPoolPub = rte_pktmbuf_pool_create("MBUF_POOL_PUB", D_NUM_MBUFS, 0, 0, 
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if(pstMbufPoolPub == NULL)
	{
		printf("rte_errno = %x, errmsg = %s\n", rte_errno, rte_strerror(rte_errno));
		return -1;
	}

    if (-1 == rte_kni_init(D_PORT_ID)) 
        rte_exit(EXIT_FAILURE, "kni init failed\n");
    
	ng_init_port(pstMbufPoolPub);
	g_pstKni = ng_alloc_kni(pstMbufPoolPub);

    // ng_init_port(pstMbufPoolPub);

    rte_eth_macaddr_get(D_PORT_ID, &g_stCpuMac);

    pstRing = ringInstance();
	if(pstRing == NULL) 
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");

    pstRing->pstInRing = rte_ring_create("in ring", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    pstRing->pstOutRing = rte_ring_create("out ring", D_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	
    uiCoreId = rte_lcore_id();

    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	rte_eal_remote_launch(pkt_process, pstMbufPoolPub, uiCoreId);

    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
	rte_eal_remote_launch(udp_server_entry, pstMbufPoolPub, uiCoreId);
	
    uiCoreId = rte_get_next_lcore(uiCoreId, 1, 0);
    rte_eal_remote_launch(tcp_server_entry, pstMbufPoolPub, uiCoreId);

    while (1) 
    {
        // rx
        iRxNum = rte_eth_rx_burst(D_PORT_ID, 0, pstRecvMbuf, D_BURST_SIZE);
        if(iRxNum > 0)
            rte_ring_sp_enqueue_burst(pstRing->pstInRing, (void**)pstRecvMbuf, iRxNum, NULL);
        
        // tx
        iTotalNum = rte_ring_sc_dequeue_burst(pstRing->pstOutRing, (void**)pstSendMbuf, D_BURST_SIZE, NULL);
		if(iTotalNum > 0)
		{
			iOffset = 0;
			while(iOffset < iTotalNum)
			{
				iTxNum = rte_eth_tx_burst(D_PORT_ID, 0, &pstSendMbuf[iOffset], iTotalNum - iOffset);
				if(iTxNum > 0)
					iOffset += iTxNum;
			}
		}
    }

}   
