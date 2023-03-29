#ifndef __UDP_H__
#define __UDP_H__

#include "common.h"

int udp_process(struct rte_mbuf *pstUdpMbuf);
int udp_out(struct rte_mempool *mbuf_pool);

// udp control block
struct localhost 
{
	int fd;

	//unsigned int status; //
	uint32_t localip; // ip --> mac
	unsigned char localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;

	unsigned char protocol;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct localhost *prev; 
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

struct offload 
{ 
	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport; 

	int protocol;

	unsigned char *data;
	uint16_t length;
	
}; 

#endif