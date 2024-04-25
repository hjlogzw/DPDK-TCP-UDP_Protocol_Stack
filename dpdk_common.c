#include "dpdk_common.h"

void print_addr(uint32_t addr, short port){
    struct in_addr tmp;
    tmp.s_addr = addr;
    printf("udp_process ---> src: %s:%d \n", inet_ntoa(tmp), port);
}

void init_port(struct rte_mempool *mbuf_pool, unsigned short portId){
    uint16_t ports = rte_eth_dev_count_avail();
    if (ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info devInfo;
    rte_eth_dev_info_get(portId, &devInfo);

    struct rte_eth_conf portConf = {
        .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
    };
    rte_eth_dev_configure(portId, 1, 1, &portConf);

    // todo 收发队列单独使用内存池
    if (rte_eth_rx_queue_setup(portId, 0, 1024, rte_eth_dev_socket_id(portId), NULL, mbuf_pool) < 0){
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    struct rte_eth_txconf txqConf = devInfo.default_txconf;
    txqConf.offloads = portConf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(portId, 0, 1024, rte_eth_dev_socket_id(portId), &txqConf) < 0){
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }

    if (rte_eth_dev_start(portId) < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}
