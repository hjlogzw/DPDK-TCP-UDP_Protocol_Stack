#ifndef __DPDK_COMMON_H__
#define __DPDK_COMMON_H__

#include <rte_eal.h> 
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_ether.h>

#define DPDK_PORT_ID    0
#define MBUF_NUM 		4095
#define RING_SIZE	1024


struct RING_CONF {
    struct rte_ring *inRing;
	struct rte_ring *outRing;
};

extern void init_port(struct rte_mempool *mbuf_pool, unsigned short portId);

#endif