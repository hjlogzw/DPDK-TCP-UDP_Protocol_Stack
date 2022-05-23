#ifndef __TCP_H__
#define __TCP_H__

#include "common.h"

int tcp_process(struct rte_mbuf *pstTcpMbuf);
int tcp_out(struct rte_mempool *pstMbufPool);

// 11种tcp连接状态
typedef enum _ENUM_TCP_STATUS 
{
	TCP_STATUS_CLOSED = 0,
	TCP_STATUS_LISTEN,
	TCP_STATUS_SYN_RCVD,
	TCP_STATUS_SYN_SENT,
	TCP_STATUS_ESTABLISHED,

	TCP_STATUS_FIN_WAIT_1,
	TCP_STATUS_FIN_WAIT_2,
	TCP_STATUS_CLOSING,
	TCP_STATUS_TIME_WAIT,

	TCP_STATUS_CLOSE_WAIT,
	TCP_STATUS_LAST_ACK

}TCP_STATUS;

// tcb control block
struct tcp_stream 
{ 
	int fd; 

	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	
	uint8_t protocol;
	
	uint16_t sport;
	uint32_t sip;

	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum

	TCP_STATUS status;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct tcp_stream *prev;
	struct tcp_stream *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;
};

struct tcp_table 
{
	int count;
	//struct tcp_stream *listener_set;	//
#if ENABLE_SINGLE_EPOLL 
	struct eventpoll *ep; // single epoll
#endif
	struct tcp_stream *tcb_set;
};

struct tcp_fragment 
{ 
	uint16_t sport;  
	uint16_t dport;  
	uint32_t seqnum;  
	uint32_t acknum;  
	uint8_t  hdrlen_off;  
	uint8_t  tcp_flags; 
	uint16_t windows;   
	uint16_t cksum;     
	uint16_t tcp_urp;  

	int optlen;
	uint32_t option[D_TCP_OPTION_LENGTH];

	unsigned char *data;
	uint32_t length;

};


#endif
