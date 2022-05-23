#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_mempool.h>
#include <rte_flow.h>

#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_log.h>
#include <rte_kni.h>

#define   D_PORT_ID           0

#define   D_MAX_PACKET_SIZE   2048
#define   D_RING_SIZE         1024
#define   D_BURST_SIZE        32

#define   D_DEFAULT_FD_NUM	  3
#define   D_MAX_FD_COUNT	  1024

#define   D_NUM_MBUFS               (4096-1)
#define   D_UDP_BUFFER_SIZE	 1024

#define   D_TCP_OPTION_LENGTH	10
#define   D_TCP_INITIAL_WINDOW  14600
#define   D_TCP_MAX_SEQ		    0xffffffff
#define   D_TCP_BUFFER_SIZE  1024
// 头插法
#define LL_ADD(item, list) do			 \
{										 \
	item->prev = NULL;					 \
	item->next = list;					 \
	if (list != NULL) list->prev = item; \
	list = item;						 \
} while(0)

#define LL_REMOVE(item, list) do 							\
{															\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;					\
	item->prev = item->next = NULL;							\
} while(0)

// 网卡的输入、输出队列
struct St_InOut_Ring 
{
	struct rte_ring *pstInRing;
	struct rte_ring *pstOutRing;
};

// arp表的单个条目
struct arp_entry 
{
	uint32_t ip;
	unsigned char hwaddr[RTE_ETHER_ADDR_LEN];

	unsigned char type;

	struct arp_entry *next;
	struct arp_entry *prev;
};

// arp表结构
struct arp_table 
{
	struct arp_entry *entries;
	int count;

	pthread_spinlock_t spinlock;
};

extern struct St_InOut_Ring *g_pstRingIns;
extern unsigned char g_ucFdTable[D_MAX_FD_COUNT];
extern struct localhost *g_pstHost;
extern struct rte_ether_addr g_stCpuMac;
extern struct arp_table *g_pstArpTbl;
extern struct tcp_table *g_pstTcpTbl;
extern unsigned char g_aucDefaultArpMac[RTE_ETHER_ADDR_LEN];

void dbg_print(char *info, unsigned char *dat, int dat_len);

// arp相关
int ng_arp_entry_insert(uint32_t ip, unsigned char *mac);
unsigned char* ng_get_dst_macaddr(uint32_t dip);
struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, unsigned char *dst_mac, 
                                uint32_t sip, uint32_t dip);

// search
struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, unsigned char proto);
void* get_hostinfo_fromfd(int iSockFd);

struct tcp_table *tcpInstance(void);
struct tcp_stream * tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

// socket api
int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol);
int nbind(int sockfd, const struct sockaddr *addr, __attribute__((unused))  socklen_t addrlen);
int nlisten(int sockfd, __attribute__((unused)) int backlog);
int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen);
ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags);
ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags);
ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen);
ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen);
int nclose(int fd);

#endif