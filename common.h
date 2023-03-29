#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#include "nty_tree.h"

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

enum EPOLL_EVENTS 
{
	EPOLLNONE 	= 0x0000,
	EPOLLIN 	= 0x0001,
	EPOLLPRI	= 0x0002,
	EPOLLOUT	= 0x0004,
	EPOLLRDNORM = 0x0040,
	EPOLLRDBAND = 0x0080,
	EPOLLWRNORM = 0x0100,
	EPOLLWRBAND = 0x0200,
	EPOLLMSG	= 0x0400,
	EPOLLERR	= 0x0008,
	EPOLLHUP 	= 0x0010,
	EPOLLRDHUP 	= 0x2000,
	EPOLLONESHOT = (1 << 30),
	EPOLLET 	= (1 << 31)

};

#define EPOLL_CTL_ADD	1
#define EPOLL_CTL_DEL	2
#define EPOLL_CTL_MOD	3

typedef union epoll_data 
{
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event 
{
	uint32_t events;
	epoll_data_t data;
};

struct epitem 
{
	RB_ENTRY(epitem) rbn;
	LIST_ENTRY(epitem) rdlink;
	int rdy; //exist in list 
	
	int sockfd;
	struct epoll_event event; 
};

static int sockfd_cmp(struct epitem *ep1, struct epitem *ep2) 
{
	if (ep1->sockfd < ep2->sockfd) return -1;
	else if (ep1->sockfd == ep2->sockfd) return 0;
	return 1;
}

RB_HEAD(_epoll_rb_socket, epitem);
RB_GENERATE_STATIC(_epoll_rb_socket, epitem, rbn, sockfd_cmp);

typedef struct _epoll_rb_socket ep_rb_tree;

struct eventpoll 
{
	int fd;

	ep_rb_tree rbr;
	int rbcnt;
	
	LIST_HEAD( ,epitem) rdlist;
	int rdnum;

	int waiting;

	pthread_mutex_t mtx; //rbtree update
	pthread_spinlock_t lock; //rdlist update
	
	pthread_cond_t cond; //block for event
	pthread_mutex_t cdmtx; //mutex for cond
	
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

// epoll
int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event);
int nepoll_create(int size);
int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event);
int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);


#endif