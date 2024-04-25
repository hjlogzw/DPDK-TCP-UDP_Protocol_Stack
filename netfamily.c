#include "dpdk_common.h"
#include "udp.h"
#include "arp.h"

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN]; 
struct RING_CONF ringInstance;

void pkg_process(void *arg){
	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;

	while(1){
		struct rte_mbuf *mbufs[32];
		unsigned rxNum = rte_ring_mc_dequeue_burst(ringInstance.inRing, (void **)mbufs, 32, NULL);
	
		for (unsigned i = 0; i < rxNum; i++){
			struct rte_ether_hdr *ether = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

			if (ether->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct  rte_ether_hdr));

				// todo 处理arp

				if (ip->next_proto_id == IPPROTO_UDP){
					// todo 处理UDP
					udp_process(mbufs[i]);
				} else if (ip->next_proto_id == IPPROTO_TCP){
					// todo 处理UDP
				} else {
					// todo 使用kni处理其他协议
				}
			} else {
				// todo 使用kni处理其他协议
			}
		}
		
	}

}


int main(int argc, char *argv[]){
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbufpool", MBUF_NUM, 0,0,RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	init_port(mbuf_pool, DPDK_PORT_ID);

	rte_eth_macaddr_get(DPDK_PORT_ID, (struct rte_ether_addr*)gSrcMac);

	// todo udp/tcp公用io
	ringInstance.inRing = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	ringInstance.outRing = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

	// todo 后续每个线程绑核，单独分配线程池
	rte_eal_remote_launch(pkg_process, mbuf_pool, rte_get_next_lcore(rte_lcore_id, 1, 0));

	// todo 收发包逻辑不放到主逻辑，各自分开
	while(1){
		struct rte_mbuf *rxMbuf[32];
		uint16_t rxNum = rte_eth_rx_burst(DPDK_PORT_ID, 0, rxMbuf, 32); 
		if (rxNum > 32) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (rxNum > 0)  {
			rte_ring_sp_enqueue_burst(ringInstance.inRing, (void **)rxMbuf, rxNum, NULL);
		}

		struct rte_mbuf *txMbuf[32];
		uint16_t txNum = rte_ring_sc_dequeue_burst(ringInstance.outRing, (void **)txMbuf, 32, NULL);
		if (txNum > 0) {
			rte_eth_tx_burst(DPDK_PORT_ID, 0, txMbuf, txNum);

			for (unsigned i = 0;i < txNum; i ++) {
				rte_pktmbuf_free(txMbuf[i]);
			}
		}
	}
}

