

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ether.h>


#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_log.h>
#include <rte_kni.h>

#include <stdio.h>
#include <math.h>
#include <arpa/inet.h>


#define ENABLE_SEND		1
#define ENABLE_ARP		1
#define ENABLE_ICMP		1
#define ENABLE_ARP_REPLY	1

#define ENABLE_DEBUG		1

#define ENABLE_TIMER		1

#define ENABLE_RINGBUFFER	1
#define ENABLE_MULTHREAD	1

#define ENABLE_UDP_APP		1

#define ENABLE_TCP_APP		1

#define ENABLE_KNI_APP			1

#define ENABLE_DDOS_DETECT		1

#define ENABLE_SINGLE_EPOLL			1


#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32
#define RING_SIZE	1024
#define MAX_PACKET_SIZE		2048
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 


#if ENABLE_SINGLE_EPOLL

#include <sys/queue.h>
#include "nty_tree.h"

enum EPOLL_EVENTS {
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

typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events;
	epoll_data_t data;
};



struct epitem {
	RB_ENTRY(epitem) rbn;
	LIST_ENTRY(epitem) rdlink;
	int rdy; //exist in list 
	
	int sockfd;
	struct epoll_event event; 
};

static int sockfd_cmp(struct epitem *ep1, struct epitem *ep2) {
	if (ep1->sockfd < ep2->sockfd) return -1;
	else if (ep1->sockfd == ep2->sockfd) return 0;
	return 1;
}


RB_HEAD(_epoll_rb_socket, epitem);
RB_GENERATE_STATIC(_epoll_rb_socket, epitem, rbn, sockfd_cmp);

typedef struct _epoll_rb_socket ep_rb_tree;

//
struct eventpoll {
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

int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event);
int nepoll_create(int size);
int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event);
int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);





#endif


#if ENABLE_ARP

#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1


#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)


struct arp_entry {

	uint32_t ip;
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN];

	uint8_t type;
	// 

	struct arp_entry *next;
	struct arp_entry *prev;

	
};

struct arp_table {

	struct arp_entry *entries;
	int count;

	pthread_spinlock_t spinlock;
};



static struct  arp_table *arpt = NULL;

static struct  arp_table *arp_table_instance(void) {

	if (arpt == NULL) {

		arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));

		pthread_spin_init(&arpt->spinlock, PTHREAD_PROCESS_SHARED);
	}

	return arpt;

}


static uint8_t* ng_get_dst_macaddr(uint32_t dip) {

	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();

	int count = table->count;
	
	for (iter = table->entries; count-- != 0 && iter != NULL;iter = iter->next) {
		if (dip == iter->ip) {
			return iter->hwaddr;
		}
	}

	return NULL;
}

static int ng_arp_entry_insert(uint32_t ip, uint8_t *mac) {

	struct arp_table *table = arp_table_instance();

	uint8_t *hwaddr = ng_get_dst_macaddr(ip);
	if (hwaddr == NULL) {

		struct arp_entry *entry = rte_malloc("arp_entry",sizeof(struct arp_entry), 0);
		if (entry) {
			memset(entry, 0, sizeof(struct arp_entry));

			entry->ip = ip;
			rte_memcpy(entry->hwaddr, mac, RTE_ETHER_ADDR_LEN);
			entry->type = 0;

			pthread_spin_lock(&table->spinlock);
			LL_ADD(entry, table->entries);
			table->count ++;
			pthread_spin_unlock(&table->spinlock);
			
		}

		return 1; //
	}

	return 0;
}

#endif

#if ENABLE_SEND

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 0, 119);

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];

#endif

#if ENABLE_KNI_APP

struct rte_kni *global_kni = NULL;


#endif

#if ENABLE_ARP_REPLY

static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#endif

#if ENABLE_RINGBUFFER

struct inout_ring {

	struct rte_ring *in;
	struct rte_ring *out;
};

static struct inout_ring *rInst = NULL;

static struct inout_ring *ringInstance(void) {

	if (rInst == NULL) {

		rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
		memset(rInst, 0, sizeof(struct inout_ring));
	}

	return rInst;
}

#endif

#if ENABLE_UDP_APP

static int udp_process(struct rte_mbuf *udpmbuf);
static int udp_out(struct rte_mempool *mbuf_pool);


#endif

#if ENABLE_TCP_APP

static int ng_tcp_process(struct rte_mbuf *tcpmbuf);
static int ng_tcp_out(struct rte_mempool *mbuf_pool);


#define TCP_OPTION_LENGTH	10

#define TCP_MAX_SEQ		4294967295

#define TCP_INITIAL_WINDOW  14600

typedef enum _NG_TCP_STATUS {

	NG_TCP_STATUS_CLOSED = 0,
	NG_TCP_STATUS_LISTEN,
	NG_TCP_STATUS_SYN_RCVD,
	NG_TCP_STATUS_SYN_SENT,
	NG_TCP_STATUS_ESTABLISHED,

	NG_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_STATUS_CLOSING,
	NG_TCP_STATUS_TIME_WAIT,

	NG_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_STATUS_LAST_ACK

} NG_TCP_STATUS;


struct ng_tcp_stream { // tcb control block

	int fd; //

	uint32_t dip;
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t dport;
	
	uint8_t protocol;
	
	uint16_t sport;
	uint32_t sip;

	uint32_t snd_nxt; // seqnum
	uint32_t rcv_nxt; // acknum

	NG_TCP_STATUS status;
#if 0
	union {

		struct {
			struct ng_tcp_stream *syn_set; //
			struct ng_tcp_stream *accept_set; //
		};
		
		struct {
			struct rte_ring *sndbuf;
			struct rte_ring *rcvbuf;
		};
	};
#else
	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;
#endif
	struct ng_tcp_stream *prev;
	struct ng_tcp_stream *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};

struct ng_tcp_table {
	int count;
	//struct ng_tcp_stream *listener_set;	//
#if ENABLE_SINGLE_EPOLL 
	struct eventpoll *ep; // single epoll
#endif
	struct ng_tcp_stream *tcb_set;
};

struct ng_tcp_fragment { 

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
	uint32_t option[TCP_OPTION_LENGTH];

	unsigned char *data;
	uint32_t length;

};


struct ng_tcp_table *tInst = NULL;

static struct ng_tcp_table *tcpInstance(void) {

	if (tInst == NULL) {

		tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
		memset(tInst, 0, sizeof(struct ng_tcp_table));
		
	}
	return tInst;
}




#endif


int gDpdkPortId = 0;



static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void ng_init_port(struct rte_mempool *mbuf_pool) {

	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); //
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); //
	
	const int num_rx_queues = 1;
	const int num_tx_queues = 1;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {

		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

	}
	
#if ENABLE_SEND
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads;
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
		
	}
#endif

	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

#if ENABLE_KNI_APP
	rte_eth_promiscuous_enable(gDpdkPortId);
#endif
}

/*
static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

	addr.s_addr = gDstIp;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));

	return 0;
}


static struct rte_mbuf * ng_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_pkt(pktdata, data, total_len);

	return mbuf;

}

*/

#if ENABLE_ARP


static int ng_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	if (!strncmp((const char *)dst_mac, (const char *)gDefaultArpMac, RTE_ETHER_ADDR_LEN)) {
		uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
		rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
	} else {
		rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	}
	eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

	// 2 arp 
	struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
	arp->arp_hardware = htons(1);
	arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp->arp_hlen = RTE_ETHER_ADDR_LEN;
	arp->arp_plen = sizeof(uint32_t);
	arp->arp_opcode = htons(opcode);

	rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

	arp->arp_data.arp_sip = sip;
	arp->arp_data.arp_tip = dip;
	
	return 0;

}

static struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_send_arp rte_pktmbuf_alloc\n");
	}

	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

	return mbuf;
}

#endif


#if 0 //ENABLE_ICMP


static uint16_t ng_checksum(uint16_t *addr, int count) {

	register long sum = 0;

	while (count > 1) {

		sum += *(unsigned short*)addr++;
		count -= 2;
	
	}

	if (count > 0) {
		sum += *(unsigned char *)addr;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}

static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	// 1 ether
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	// 2 ip
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_ICMP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 icmp 
	struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
	icmp->icmp_code = 0;
	icmp->icmp_ident = id;
	icmp->icmp_seq_nb = seqnb;

	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = ng_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));

	return 0;
}


static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
		uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

	const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}

	
	mbuf->pkt_len = total_length;
	mbuf->data_len = total_length;

	uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
	ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);

	return mbuf;

}


#endif

static void 
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}


#if ENABLE_TIMER

static void
arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	   void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

#if 0
	struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, ahdr->arp_data.arp_sha.addr_bytes, 
		ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

	rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
	rte_pktmbuf_free(arpbuf);

#endif
	
	int i = 0;
	for (i = 1;i <= 254;i ++) {

		uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
/*
		struct in_addr addr;
		addr.s_addr = dstip;
		printf("arp ---> src: %s \n", inet_ntoa(addr));
*/
		struct rte_mbuf *arpbuf = NULL;
		uint8_t *dstmac = ng_get_dst_macaddr(dstip);
		if (dstmac == NULL) {

			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
		
		} else {

			arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
		}

		//rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
		//rte_pktmbuf_free(arpbuf);
		rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1, NULL);
		
	}
	
}


#endif

#if ENABLE_MULTHREAD



static int pkt_process(void *arg) {

	struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
	struct inout_ring *ring = ringInstance();

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);
		
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

			if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

				struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));

				
#if 1 // arp table
				
				ng_arp_entry_insert(iphdr->src_addr, ehdr->s_addr.addr_bytes);
				
#endif
			
				if (iphdr->next_proto_id == IPPROTO_UDP) {

					udp_process(mbufs[i]);
					// 53 --> 
					// 
					
				} else if (iphdr->next_proto_id == IPPROTO_TCP) {

					ng_tcp_process(mbufs[i]);
					
				} else {

					rte_kni_tx_burst(global_kni, mbufs, num_recvd);
					
					printf("tcp/udp --> rte_kni_handle_request\n");

				}

				
			} else {
			// ifconfig vEth0 192.168.0.119 up

				rte_kni_tx_burst(global_kni, mbufs, num_recvd);
				
				printf("ip --> rte_kni_handle_request\n");

			}

			
		}

		rte_kni_handle_request(global_kni);

#if ENABLE_UDP_APP

		udp_out(mbuf_pool);

#endif


#if ENABLE_TCP_APP

		ng_tcp_out(mbuf_pool);

#endif

	}

	return 0;
}


#endif


#if ENABLE_UDP_APP



struct localhost { // 

	int fd;

	//unsigned int status; //
	uint32_t localip; // ip --> mac
	uint8_t localmac[RTE_ETHER_ADDR_LEN];
	uint16_t localport;

	uint8_t protocol;

	struct rte_ring *sndbuf;
	struct rte_ring *rcvbuf;

	struct localhost *prev; //
	struct localhost *next;

	pthread_cond_t cond;
	pthread_mutex_t mutex;

};

static struct localhost *lhost = NULL;

#define DEFAULT_FD_NUM	3

#define MAX_FD_COUNT	1024

static unsigned char fd_table[MAX_FD_COUNT] = {0};

static int get_fd_frombitmap(void) {

	int fd = DEFAULT_FD_NUM;
	for ( ;fd < MAX_FD_COUNT;fd ++) {
		if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
			fd_table[fd/8] |= (0x1 << (fd % 8));
			return fd;
		}
	}

	return -1;
	
}

static int set_fd_frombitmap(int fd) {

	if (fd >= MAX_FD_COUNT) return -1;

	fd_table[fd/8] &= ~(0x1 << (fd % 8));

	return 0;
}

static struct ng_tcp_stream *get_accept_tcb(uint16_t dport) {

	struct ng_tcp_stream *apt;
	struct ng_tcp_table *table = tcpInstance();
	for (apt = table->tcb_set;apt != NULL;apt = apt->next) {
		if (dport == apt->dport && apt->fd == -1) {
			return apt;
		}
	}

	return NULL;
}

//fd --> udp, tcp, epoll

static void* get_hostinfo_fromfd(int sockfd) {

	struct localhost *host;

	for (host = lhost; host != NULL;host = host->next) {

		if (sockfd == host->fd) {
			return host;
		}

	}

#if ENABLE_TCP_APP

	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpInstance();
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}

#endif

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

static struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {

	struct localhost *host;

	for (host = lhost; host != NULL;host = host->next) {

		if (dip == host->localip && port == host->localport && proto == host->protocol) {
			return host;
		}

	}

	
	return NULL;
	
}

// arp
struct offload { //

	uint32_t sip;
	uint32_t dip;

	uint16_t sport;
	uint16_t dport; //

	int protocol;

	unsigned char *data;
	uint16_t length;
	
}; 


static int udp_process(struct rte_mbuf *udpmbuf) {

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

	
	struct in_addr addr;
	addr.s_addr = iphdr->src_addr;
	printf("udp_process ---> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));

	struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
	if (host == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -3;
	} 


	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) {
		rte_pktmbuf_free(udpmbuf);
		return -1;
	}

	ol->dip = iphdr->dst_addr;
	ol->sip = iphdr->src_addr;
	ol->sport = udphdr->src_port;
	ol->dport = udphdr->dst_port;

	
	ol->protocol = IPPROTO_UDP;
	ol->length = ntohs(udphdr->dgram_len);

	ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
	if (ol->data == NULL) {

		rte_pktmbuf_free(udpmbuf);
		rte_free(ol);

		return -2;

	}
	rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));

	rte_ring_mp_enqueue(host->rcvbuf, ol); // recv buffer

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

	rte_pktmbuf_free(udpmbuf);

	return 0;
}


static int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	unsigned char *data, uint16_t total_len) {

	// encode 

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = sport;
	udp->dst_port = dport;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	return 0;
}


static struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
	uint8_t *data, uint16_t length) {

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
		data, total_len);

	return mbuf;

}


// offload --> mbuf
static int udp_out(struct rte_mempool *mbuf_pool) {

	struct localhost *host;
	for (host = lhost; host != NULL; host = host->next) {

		struct offload *ol;
		int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
		if (nb_snd < 0) continue;

		struct in_addr addr;
		addr.s_addr = ol->dip;
		printf("udp_out ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
			
		uint8_t *dstmac = ng_get_dst_macaddr(ol->dip); //
		if (dstmac == NULL) {

			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				ol->sip, ol->dip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(host->sndbuf, ol);
			
		} else {

			struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
				host->localmac, dstmac, ol->data, ol->length);

			
			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);

		}
		

	}

	return 0;
}

// hook

static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {

	int fd = get_fd_frombitmap(); //

	if (type == SOCK_DGRAM) {

		struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
		if (host == NULL) {
			return -1;
		}
		memset(host, 0, sizeof(struct localhost));

		host->fd = fd;
		
		host->protocol = IPPROTO_UDP;

		host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->rcvbuf == NULL) {

			rte_free(host);
			return -1;
		}

	
		host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->sndbuf == NULL) {

			rte_ring_free(host->rcvbuf);

			rte_free(host);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		LL_ADD(host, lhost);
		
	} else if (type == SOCK_STREAM) {


		struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
		if (stream == NULL) {
			return -1;
		}
		memset(stream, 0, sizeof(struct ng_tcp_stream));

		stream->fd = fd;
		stream->protocol = IPPROTO_TCP;
		stream->next = stream->prev = NULL;

		stream->rcvbuf = rte_ring_create("tcp recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->rcvbuf == NULL) {

			rte_free(stream);
			return -1;
		}

	
		stream->sndbuf = rte_ring_create("tcp send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->sndbuf == NULL) {

			rte_ring_free(stream->rcvbuf);

			rte_free(stream);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		struct ng_tcp_table *table = tcpInstance();
		LL_ADD(stream, table->tcb_set); //hash
		// get_stream_from_fd();
	}

	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) {

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct localhost *host = (struct localhost *)hostinfo;
	if (host->protocol == IPPROTO_UDP) {
		
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		host->localport = laddr->sin_port;
		rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	} else if (host->protocol == IPPROTO_TCP) {

		struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
		
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		stream->dport = laddr->sin_port;
		rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

		stream->status = NG_TCP_STATUS_CLOSED;
		
	}

	return 0;

}


static int nlisten(int sockfd, __attribute__((unused)) int backlog) { //

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {
		stream->status = NG_TCP_STATUS_LISTEN;
	}

	return 0;
}


static int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_stream *apt = NULL;

		pthread_mutex_lock(&stream->mutex);
		while((apt = get_accept_tcb(stream->dport)) == NULL) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		} 
		pthread_mutex_unlock(&stream->mutex);

		apt->fd = get_fd_frombitmap();

		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = apt->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

		return apt->fd;
	}

	return -1;
}


static ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags) {

	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (fragment == NULL) {
			return -2;
		}

		memset(fragment, 0, sizeof(struct ng_tcp_fragment));

		fragment->dport = stream->sport;
		fragment->sport = stream->dport;

		fragment->acknum = stream->rcv_nxt;
		fragment->seqnum = stream->snd_nxt;

		fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		fragment->windows = TCP_INITIAL_WINDOW;
		fragment->hdrlen_off = 0x50;


		fragment->data = rte_malloc("unsigned char *", len+1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, len+1);

		rte_memcpy(fragment->data, buf, len);
		fragment->length = len;
		length = fragment->length;

		// int nb_snd = 0;
		rte_ring_mp_enqueue(stream->sndbuf, fragment);

	}

	
	return length;
}

// recv 32
// recv 
static ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
	
	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = NULL;
		int nb_rcv = 0;

		printf("rte_ring_mc_dequeue before\n");
		pthread_mutex_lock(&stream->mutex);
		while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);
		printf("rte_ring_mc_dequeue after\n");

		if (fragment->length > len) {

			rte_memcpy(buf, fragment->data, len);

			uint32_t i = 0;
			for(i = 0;i < fragment->length-len;i ++) {
				fragment->data[i] = fragment->data[len+i];
			}
			fragment->length = fragment->length-len;
			length = fragment->length;

			rte_ring_mp_enqueue(stream->rcvbuf, fragment);

		} else if (fragment->length == 0) {

			rte_free(fragment);
			return 0;
		
		} else {

			rte_memcpy(buf, fragment->data, fragment->length);
			length = fragment->length;

			rte_free(fragment->data);
			fragment->data = NULL;

			rte_free(fragment);
			
		}

	}

	return length;
}


static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {

	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	struct offload *ol = NULL;
	unsigned char *ptr = NULL;
	
	struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
	
	int nb = -1;
	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);
	

	saddr->sin_port = ol->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

	if (len < ol->length) {

		rte_memcpy(buf, ol->data, len);

		ptr = rte_malloc("unsigned char *", ol->length-len, 0);
		rte_memcpy(ptr, ol->data+len, ol->length-len);

		ol->length -= len;
		rte_free(ol->data);
		ol->data = ptr;
		
		rte_ring_mp_enqueue(host->rcvbuf, ol);

		return len;
		
	} else {

		int length = ol->length;
		rte_memcpy(buf, ol->data, ol->length);
		
		rte_free(ol->data);
		rte_free(ol);
		
		return length;
	}

	

}

static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {

	
	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->length = len;

	struct in_addr addr;
	addr.s_addr = ol->dip;
	printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
	

	ol->data = rte_malloc("unsigned char *", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuf, ol);

	return len;
}

static int nclose(int fd) {

	
	void *hostinfo =  get_hostinfo_fromfd(fd);
	if (hostinfo == NULL) return -1;

	struct localhost *host = (struct localhost*)hostinfo;
	if (host->protocol == IPPROTO_UDP) {

		LL_REMOVE(host, lhost);

		if (host->rcvbuf) {
			rte_ring_free(host->rcvbuf);
		}
		if (host->sndbuf) {
			rte_ring_free(host->sndbuf);
		}

		rte_free(host);

		set_fd_frombitmap(fd);
		
	} else if (host->protocol == IPPROTO_TCP) { 

		struct ng_tcp_stream *stream = (struct ng_tcp_stream*)hostinfo;

		if (stream->status != NG_TCP_STATUS_LISTEN) {
			
			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;

			printf("nclose --> enter last ack\n");
			fragment->data = NULL;
			fragment->length = 0;
			fragment->sport = stream->dport;
			fragment->dport = stream->sport;

			fragment->seqnum = stream->snd_nxt;
			fragment->acknum = stream->rcv_nxt;

			fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;

			rte_ring_mp_enqueue(stream->sndbuf, fragment);
			stream->status = NG_TCP_STATUS_LAST_ACK;

			
			set_fd_frombitmap(fd);

		} else { // nsocket

			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);	

			rte_free(stream);

		}
	}

	return 0;
}







#define UDP_APP_RECV_BUFFER_SIZE	128

// 
static int udp_server_entry(__attribute__((unused))  void *arg) {

	int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
	if (connfd == -1) {
		printf("sockfd failed\n");
		return -1;
	} 

	struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
	memset(&localaddr, 0, sizeof(struct sockaddr_in));

	localaddr.sin_port = htons(8889);
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = inet_addr("192.168.0.119"); // 0.0.0.0
	

	nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

	char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
	socklen_t addrlen = sizeof(clientaddr);
	while (1) {

		if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, 
			(struct sockaddr*)&clientaddr, &addrlen) < 0) {

			continue;

		} else {

			printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), 
				ntohs(clientaddr.sin_port), buffer);
			nsendto(connfd, buffer, strlen(buffer), 0, 
				(struct sockaddr*)&clientaddr, sizeof(clientaddr));
		}

	}

	nclose(connfd);

}




#endif


#if ENABLE_TCP_APP // ngtcp


// <sip, dip, sport, dport, proto> --> tcb
//
static struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto

	struct ng_tcp_table *table = tcpInstance();

	struct ng_tcp_stream *iter;
	for (iter = table->tcb_set;iter != NULL; iter = iter->next) { // established

		if (iter->sip == sip && iter->dip == dip && 
			iter->sport == sport && iter->dport == dport) {
			return iter;
		}

	}

	for (iter = table->tcb_set;iter != NULL; iter = iter->next) {

		if (iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) { // listen
			return iter;
		}

	}

	return NULL;
}

static struct ng_tcp_stream * ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto

	// tcp --> status
	struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
	if (stream == NULL) return NULL;

	stream->sip = sip;
	stream->dip = dip;
	stream->sport = sport;
	stream->dport = dport;
	stream->protocol = IPPROTO_TCP;
	stream->fd = -1; //unused

	// 
	stream->status = NG_TCP_STATUS_LISTEN;

	printf("ng_tcp_stream_create\n");
	//
	char sbufname[32] = {0};
	sprintf(sbufname, "sndbuf%x%d", sip, sport);
	stream->sndbuf = rte_ring_create(sbufname, RING_SIZE, rte_socket_id(), 0);
	
	char rbufname[32] = {0};
	sprintf(rbufname, "bufname%x%d", sip, sport);
	stream->rcvbuf = rte_ring_create(rbufname, RING_SIZE, rte_socket_id(), 0);
	
	// seq num
	uint32_t next_seed = time(NULL);
	stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
	rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
	rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

	//struct ng_tcp_table *table = tcpInstance();
	//LL_ADD(stream, table->tcb_set);

	return stream;
}



static int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  {
		//stream --> listenfd
		if (stream->status == NG_TCP_STATUS_LISTEN) {

			struct ng_tcp_table *table = tcpInstance();
			struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
			LL_ADD(syn, table->tcb_set);


			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;
			memset(fragment, 0, sizeof(struct ng_tcp_fragment));

			fragment->sport = tcphdr->dst_port;
			fragment->dport = tcphdr->src_port;

			struct in_addr addr;
			addr.s_addr = syn->sip;
			printf("tcp ---> src: %s:%d ", inet_ntoa(addr), ntohs(tcphdr->src_port));

			
			addr.s_addr = syn->dip;
			printf("  ---> dst: %s:%d \n", inet_ntoa(addr), ntohs(tcphdr->dst_port));

			fragment->seqnum = syn->snd_nxt;
			fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
			syn->rcv_nxt = fragment->acknum;
			
			fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;
			
			fragment->data = NULL;
			fragment->length = 0;

			rte_ring_mp_enqueue(syn->sndbuf, fragment);
			
			syn->status = NG_TCP_STATUS_SYN_RCVD;
		}

	}

	return 0;
}


static int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_SYN_RCVD) {

			uint32_t acknum = ntohl(tcphdr->recv_ack);
			if (acknum == stream->snd_nxt + 1) {
				// 
			}

			stream->status = NG_TCP_STATUS_ESTABLISHED;

			// accept
			struct ng_tcp_stream *listener = ng_tcp_stream_search(0, 0, 0, stream->dport);
			if (listener == NULL) {
				rte_exit(EXIT_FAILURE, "ng_tcp_stream_search failed\n");
			}

			pthread_mutex_lock(&listener->mutex);
			pthread_cond_signal(&listener->cond);
			pthread_mutex_unlock(&listener->mutex);
			
#if ENABLE_SINGLE_EPOLL

			struct ng_tcp_table *table = tcpInstance();
			epoll_event_callback(table->ep, listener->fd, EPOLLIN);

#endif

		}

	}
	return 0;
}

static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {

	// recv buffer
	struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (rfragment == NULL) return -1;
	memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

	rfragment->dport = ntohs(tcphdr->dst_port);
	rfragment->sport = ntohs(tcphdr->src_port);

	uint8_t hdrlen = tcphdr->data_off >> 4;
	int payloadlen = tcplen - hdrlen * 4; //
	if (payloadlen > 0) {
		
		uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

		rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
		if (rfragment->data == NULL) {
			rte_free(rfragment);
			return -1;
		}
		memset(rfragment->data, 0, payloadlen+1);

		rte_memcpy(rfragment->data, payload, payloadlen);
		rfragment->length = payloadlen;

	} else if (payloadlen == 0) {

		rfragment->length = 0;
		rfragment->data = NULL;

	}
	rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

	pthread_mutex_lock(&stream->mutex);
	pthread_cond_signal(&stream->cond);
	pthread_mutex_unlock(&stream->mutex);

	return 0;
}

static int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
	if (ackfrag == NULL) return -1;
	memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

	ackfrag->dport = tcphdr->src_port;
	ackfrag->sport = tcphdr->dst_port;

	// remote
	
	printf("ng_tcp_send_ackpkt: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));
	

	ackfrag->acknum = stream->rcv_nxt;
	ackfrag->seqnum = stream->snd_nxt;

	ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
	ackfrag->windows = TCP_INITIAL_WINDOW;
	ackfrag->hdrlen_off = 0x50;
	ackfrag->data = NULL;
	ackfrag->length = 0;
	
	rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

	return 0;
}

static int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {

	if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
		//
	} 
	if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) { //

		// recv buffer
#if 0
		struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (rfragment == NULL) return -1;
		memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

		rfragment->dport = ntohs(tcphdr->dst_port);
		rfragment->sport = ntohs(tcphdr->src_port);

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;
		if (payloadlen > 0) {
			
			uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

			rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
			if (rfragment->data == NULL) {
				rte_free(rfragment);
				return -1;
			}
			memset(rfragment->data, 0, payloadlen+1);

			rte_memcpy(rfragment->data, payload, payloadlen);
			rfragment->length = payloadlen;

			printf("tcp : %s\n", rfragment->data);
		}
		rte_ring_mp_enqueue(stream->rcvbuf, rfragment);
#else

		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);
		
#if ENABLE_SINGLE_EPOLL

		struct ng_tcp_table *table = tcpInstance();
		epoll_event_callback(table->ep, stream->fd, EPOLLIN);

#endif


#endif


#if 0
		// ack pkt
		struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (ackfrag == NULL) return -1;
		memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

		ackfrag->dport = tcphdr->src_port;
		ackfrag->sport = tcphdr->dst_port;

		// remote
		
		printf("ng_tcp_handle_established: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));
		
		
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		// local 
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		//ackfrag->

		ackfrag->acknum = stream->rcv_nxt;
		ackfrag->seqnum = stream->snd_nxt;

		ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
		ackfrag->windows = TCP_INITIAL_WINDOW;
		ackfrag->hdrlen_off = 0x50;
		ackfrag->data = NULL;
		ackfrag->length = 0;
		
		rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

#else

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;
		
		stream->rcv_nxt = stream->rcv_nxt + payloadlen;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(stream, tcphdr);
		
#endif
		// echo pkt
#if 0
		struct ng_tcp_fragment *echofrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (echofrag == NULL) return -1;
		memset(echofrag, 0, sizeof(struct ng_tcp_fragment));

		echofrag->dport = tcphdr->src_port;
		echofrag->sport = tcphdr->dst_port;

		echofrag->acknum = stream->rcv_nxt;
		echofrag->seqnum = stream->snd_nxt;

		echofrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		echofrag->windows = TCP_INITIAL_WINDOW;
		echofrag->hdrlen_off = 0x50;

		uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

		echofrag->data = rte_malloc("unsigned char *", payloadlen, 0);
		if (echofrag->data == NULL) {
			rte_free(echofrag);
			return -1;
		}
		memset(echofrag->data, 0, payloadlen);

		rte_memcpy(echofrag->data, payload, payloadlen);
		echofrag->length = payloadlen;

		rte_ring_mp_enqueue(stream->sndbuf, echofrag);
#endif

	}
	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

	}
	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

		stream->status = NG_TCP_STATUS_CLOSE_WAIT;

#if 0

		struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (rfragment == NULL) return -1;
		memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

		rfragment->dport = ntohs(tcphdr->dst_port);
		rfragment->sport = ntohs(tcphdr->src_port);

		uint8_t hdrlen = tcphdr->data_off >> 4;
		int payloadlen = tcplen - hdrlen * 4;

		rfragment->length = 0;
		rfragment->data = NULL;
		
		rte_ring_mp_enqueue(stream->rcvbuf, rfragment);
		
#else

		ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);

#if ENABLE_SINGLE_EPOLL

		struct ng_tcp_table *table = tcpInstance();
		epoll_event_callback(table->ep, stream->fd, EPOLLIN);

#endif


#endif
		// send ack ptk
		stream->rcv_nxt = stream->rcv_nxt + 1;
		stream->snd_nxt = ntohl(tcphdr->recv_ack);
		
		ng_tcp_send_ackpkt(stream, tcphdr);

	}

	return 0;
}

static int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) { //

		if (stream->status == NG_TCP_STATUS_CLOSE_WAIT) {

			

		}

	}

	
	return 0;

}

static int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {

	if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

		if (stream->status == NG_TCP_STATUS_LAST_ACK) {

			stream->status = NG_TCP_STATUS_CLOSED;

			printf("ng_tcp_handle_last_ack\n");
			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);

			rte_ring_free(stream->sndbuf);
			rte_ring_free(stream->rcvbuf);

			rte_free(stream);

		}

	}

	return 0;
}

// <tcb> --> tcp
static int ng_tcp_process(struct rte_mbuf *tcpmbuf) {

	struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
	struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);	

	// tcphdr, rte_ipv4_udptcp_cksum
	uint16_t tcpcksum = tcphdr->cksum;
	tcphdr->cksum = 0;
	uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
	
#if 1 //
	if (cksum != tcpcksum) { //
		printf("cksum: %x, tcp cksum: %x\n", cksum, tcpcksum);
		rte_pktmbuf_free(tcpmbuf);
		return -1;
	}
#endif

	struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, 
		tcphdr->src_port, tcphdr->dst_port);
	if (stream == NULL) { 
		rte_pktmbuf_free(tcpmbuf);
		return -2;
	}

	switch (stream->status) {

		case NG_TCP_STATUS_CLOSED: //client 
			break;
			
		case NG_TCP_STATUS_LISTEN: // server
			ng_tcp_handle_listen(stream, tcphdr, iphdr);
			break;

		case NG_TCP_STATUS_SYN_RCVD: // server
			ng_tcp_handle_syn_rcvd(stream, tcphdr);
			break;

		case NG_TCP_STATUS_SYN_SENT: // client
			break;

		case NG_TCP_STATUS_ESTABLISHED: { // server | client

			int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
			
			ng_tcp_handle_established(stream, tcphdr, tcplen);
			
			break;
		}
		case NG_TCP_STATUS_FIN_WAIT_1: //  ~client
			break;
			
		case NG_TCP_STATUS_FIN_WAIT_2: // ~client
			break;
			
		case NG_TCP_STATUS_CLOSING: // ~client
			break;
			
		case NG_TCP_STATUS_TIME_WAIT: // ~client
			break;

		case NG_TCP_STATUS_CLOSE_WAIT: // ~server
			ng_tcp_handle_close_wait(stream, tcphdr);
			break;
			
		case NG_TCP_STATUS_LAST_ACK:  // ~server
			ng_tcp_handle_last_ack(stream, tcphdr);
			break;

	}

	rte_pktmbuf_free(tcpmbuf);

	return 0;
}


static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->sport;
	tcp->dst_port = fragment->dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);

	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;

	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return 0;
}


static struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// mempool --> mbuf

	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

	return mbuf;

}


// struct localhost , struct tcp_stream

static int ng_tcp_out(struct rte_mempool *mbuf_pool) {

	struct ng_tcp_table *table = tcpInstance();
	
	struct ng_tcp_stream *stream;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {

		if (stream->sndbuf == NULL) continue; // listener

		struct ng_tcp_fragment *fragment = NULL;		
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip); // 
		if (dstmac == NULL) {

			//printf("ng_send_arp\n");
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				stream->dip, stream->sip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(stream->sndbuf, fragment);

		} else {

			struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);

			if (fragment->data != NULL)
				rte_free(fragment->data);
			
			rte_free(fragment);
		}

	}

	return 0;
}



#if ENABLE_SINGLE_EPOLL


// 3 + 1

int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event) {

	struct epitem tmp;
	tmp.sockfd = sockid;
	struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
	if (!epi) {
		printf("rbtree not exist\n");
		return -1;
	}
	if (epi->rdy) {
		epi->event.events |= event;
		return 1;
	} 

	printf("epoll_event_callback --> %d\n", epi->sockfd);
	
	pthread_spin_lock(&ep->lock);
	epi->rdy = 1;
	LIST_INSERT_HEAD(&ep->rdlist, epi, rdlink);
	ep->rdnum ++;
	pthread_spin_unlock(&ep->lock);

	pthread_mutex_lock(&ep->cdmtx);

	pthread_cond_signal(&ep->cond);
	pthread_mutex_unlock(&ep->cdmtx);

}

// eventpoll --> tcp_table->ep;
int nepoll_create(int size) {

	if (size <= 0) return -1;

	// epfd --> struct eventpoll
	int epfd = get_fd_frombitmap(); //tcp, udp
	
	struct eventpoll *ep = (struct eventpoll*)rte_malloc("eventpoll", sizeof(struct eventpoll), 0);
	if (!ep) {
		set_fd_frombitmap(epfd);
		return -1;
	}

	struct ng_tcp_table *table = tcpInstance();
	table->ep = ep;
	
	ep->fd = epfd;
	ep->rbcnt = 0;
	RB_INIT(&ep->rbr);
	LIST_INIT(&ep->rdlist);

	if (pthread_mutex_init(&ep->mtx, NULL)) {
		free(ep);
		set_fd_frombitmap(epfd);
		
		return -2;
	}

	if (pthread_mutex_init(&ep->cdmtx, NULL)) {
		pthread_mutex_destroy(&ep->mtx);
		free(ep);
		set_fd_frombitmap(epfd);
		return -2;
	}

	if (pthread_cond_init(&ep->cond, NULL)) {
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		free(ep);
		set_fd_frombitmap(epfd);
		return -2;
	}

	if (pthread_spin_init(&ep->lock, PTHREAD_PROCESS_SHARED)) {
		pthread_cond_destroy(&ep->cond);
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		free(ep);

		set_fd_frombitmap(epfd);
		return -2;
	}

	return epfd;

}


int nepoll_ctl(int epfd, int op, int sockid, struct epoll_event *event) {
	
	struct eventpoll *ep = (struct eventpoll*)get_hostinfo_fromfd(epfd);
	if (!ep || (!event && op != EPOLL_CTL_DEL)) {
		errno = -EINVAL;
		return -1;
	}

	if (op == EPOLL_CTL_ADD) {

		pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) {
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}

		epi = (struct epitem*)rte_malloc("epitem", sizeof(struct epitem), 0);
		if (!epi) {
			pthread_mutex_unlock(&ep->mtx);
			rte_errno = -ENOMEM;
			return -1;
		}
		
		epi->sockfd = sockid;
		memcpy(&epi->event, event, sizeof(struct epoll_event));

		epi = RB_INSERT(_epoll_rb_socket, &ep->rbr, epi);

		ep->rbcnt ++;
		
		pthread_mutex_unlock(&ep->mtx);

	} else if (op == EPOLL_CTL_DEL) {

		pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (!epi) {
			
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}
		
		epi = RB_REMOVE(_epoll_rb_socket, &ep->rbr, epi);
		if (!epi) {
			
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}

		ep->rbcnt --;
		free(epi);
		
		pthread_mutex_unlock(&ep->mtx);

	} else if (op == EPOLL_CTL_MOD) {

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) {
			epi->event.events = event->events;
			epi->event.events |= EPOLLERR | EPOLLHUP;
		} else {
			rte_errno = -ENOENT;
			return -1;
		}

	} 

	return 0;

}


int nepoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {

	

	struct eventpoll *ep = (struct eventpoll*)get_hostinfo_fromfd(epfd);;
	if (!ep || !events || maxevents <= 0) {
		rte_errno = -EINVAL;
		return -1;
	}

	if (pthread_mutex_lock(&ep->cdmtx)) {
		if (rte_errno == EDEADLK) {
			printf("epoll lock blocked\n");
		}
	}

	
	while (ep->rdnum == 0 && timeout != 0) {

		ep->waiting = 1;
		if (timeout > 0) {

			struct timespec deadline;

			clock_gettime(CLOCK_REALTIME, &deadline);
			if (timeout >= 1000) {
				int sec;
				sec = timeout / 1000;
				deadline.tv_sec += sec;
				timeout -= sec * 1000;
			}

			deadline.tv_nsec += timeout * 1000000;

			if (deadline.tv_nsec >= 1000000000) {
				deadline.tv_sec++;
				deadline.tv_nsec -= 1000000000;
			}

			int ret = pthread_cond_timedwait(&ep->cond, &ep->cdmtx, &deadline);
			if (ret && ret != ETIMEDOUT) {
				printf("pthread_cond_timewait\n");
				
				pthread_mutex_unlock(&ep->cdmtx);
				
				return -1;
			}
			timeout = 0;
		} else if (timeout < 0) {

			int ret = pthread_cond_wait(&ep->cond, &ep->cdmtx);
			if (ret) {
				printf("pthread_cond_wait\n");
				pthread_mutex_unlock(&ep->cdmtx);

				return -1;
			}
		}
		ep->waiting = 0; 

	}

	pthread_mutex_unlock(&ep->cdmtx);

	pthread_spin_lock(&ep->lock);

	int cnt = 0;
	int num = (ep->rdnum > maxevents ? maxevents : ep->rdnum);
	int i = 0;
	
	while (num != 0 && !LIST_EMPTY(&ep->rdlist)) { //EPOLLET

		struct epitem *epi = LIST_FIRST(&ep->rdlist);
		LIST_REMOVE(epi, rdlink);
		epi->rdy = 0;

		memcpy(&events[i++], &epi->event, sizeof(struct epoll_event));
		
		num --;
		cnt ++;
		ep->rdnum --;
	}
	
	pthread_spin_unlock(&ep->lock);

	return cnt;
}

#endif



#define BUFFER_SIZE	1024


#if ENABLE_SINGLE_EPOLL

static int tcp_server_entry(__attribute__((unused))  void *arg)  {

	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

	nlisten(listenfd, 10);

	int epfd = nepoll_create(1); // event poll

	struct epoll_event ev, events[128];
	ev.events = EPOLLIN;
	ev.data.fd = listenfd;
	nepoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
	
	char buff[BUFFER_SIZE] = {0};
	while(1) {

		int nready = nepoll_wait(epfd, events, 128, 5);
		if (nready < 0) continue;
		
		int i = 0;
		for (i = 0;i < nready;i ++) {

			if (listenfd == events[i].data.fd) {

				
				struct sockaddr_in client;
				socklen_t len = sizeof(client);
				int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

				struct epoll_event ev;
				ev.events = EPOLLIN;
				ev.data.fd = connfd;
				nepoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);

			} else { // clientfd

				int connfd = events[i].data.fd;
				
				int n = nrecv(connfd, buff, BUFFER_SIZE, 0); //block
				if (n > 0) {
					printf("recv: %s\n", buff);
					nsend(connfd, buff, n, 0);

				} else {

					nepoll_ctl(epfd, EPOLL_CTL_DEL, connfd, NULL);
					nclose(connfd);
					
				} 

			}

		}
	}

}


#else


// hook
static int tcp_server_entry(__attribute__((unused))  void *arg)  {

	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

	nlisten(listenfd, 10);

	while (1) {
		
		struct sockaddr_in client;
		socklen_t len = sizeof(client);
		int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

		char buff[BUFFER_SIZE] = {0};
		while (1) {

			int n = nrecv(connfd, buff, BUFFER_SIZE, 0); //block
			if (n > 0) {
				printf("recv: %s\n", buff);
				nsend(connfd, buff, n, 0);

			} else if (n == 0) {

				nclose(connfd);
				break;
			} else { //nonblock

			}
		}

	}
	nclose(listenfd);
	

}

#endif


#endif


#if ENABLE_KNI_APP
// ifconfig vEth0 up/down


// config_network_if
// rte_kni_handle_request
static int ng_config_network_if(uint16_t port_id, uint8_t if_up) {

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

	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", gDpdkPortId);
	conf.group_id = gDpdkPortId;
	conf.mbuf_size = MAX_PACKET_SIZE;
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)conf.mac_addr);
	rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);

	print_ethaddr("ng_alloc_kni: ", (struct rte_ether_addr *)conf.mac_addr);

/*
	struct rte_eth_dev_info dev_info;
	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);
	*/


	struct rte_kni_ops ops;
	memset(&ops, 0, sizeof(ops));

	ops.port_id = gDpdkPortId;
	ops.config_network_if = ng_config_network_if;
	

	kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);	
	if (!kni_hanlder) {
		rte_exit(EXIT_FAILURE, "Failed to create kni for port : %d\n", gDpdkPortId);
	}
	
	return kni_hanlder;
}



#endif


#if ENABLE_DDOS_DETECT


#define CAPTURE_WINDOWS		256

static double tresh = 1200.0;

static uint32_t p_setbits[CAPTURE_WINDOWS] = {0};
static uint32_t p_totbits[CAPTURE_WINDOWS] = {0};
static double p_entropy[CAPTURE_WINDOWS] = {0};
static int pkt_idx = 0;

/*
 23651/17408, E(nan)
 1805328/4456448 Entropy(nan), Total_Entropy(4339971.575790)
 
  23526/17408, E(nan)
 1805203/4456448 Entropy(nan), Total_Entropy(4339902.272671)
 
  17847/17408, E(nan)
 1799524/4456448 Entropy(nan), Total_Entropy(4336731.547140)
 
  17670/17408, E(nan)
 1799347/4456448 Entropy(nan), Total_Entropy(4336632.027009)
 
  17774/17408, E(nan)
 1799451/4456448 Entropy(nan), Total_Entropy(4336690.507219)

 */
static double ddos_entropy(double set_bits, double total_bits) {

	return ( - set_bits) * (log2(set_bits) - log2(total_bits)) // 1 
	- (total_bits - set_bits) * (log2(total_bits - set_bits) - log2(total_bits))
	+ log2(total_bits);

}


static uint32_t count_bit(uint8_t *msg, const uint32_t length) {
	
#if 0
	uint32_t v; // count bits set in this (32-bit value)
	uint32_t c, set_bits = 0; // store the total here
	static const int S[5] = {1, 2, 4, 8, 16}; // Magic Binary Numbers
	static const int B[5] = {0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF, 0x0000FFFF};


	uint32_t *ptr = (uint32_t *)msg;
	uint32_t *end = (uint32_t *)msg + length;

	

	while (ptr < end) {

		v = *ptr++;
		
		c = v - ((v >> S[0]) & B[0]);
		c = ((c >> S[1]) & B[1]) + (c & B[1]);
		c = ((c >> S[2]) + c) & B[2];
		c = ((c >> S[3]) + c) & B[3];
		c = ((c >> S[4]) + c) & B[4];

		set_bits += c;
	}
#else

	uint64_t v, set_bits = 0;
   	const uint64_t *ptr = (uint64_t *) msg;
   	const uint64_t *end = (uint64_t *) (msg + length);
   	
	do {
      v = *(ptr++);
      v = v - ((v >> 1) & 0x5555555555555555);                    // reuse input as temporary
      v = (v & 0x3333333333333333) + ((v >> 2) & 0x3333333333333333);     // temp
      v = (v + (v >> 4)) & 0x0F0F0F0F0F0F0F0F;
      set_bits += (v * 0x0101010101010101) >> (sizeof(v) - 1) * 8; // count

    } while(end > ptr);

#endif
	return set_bits;
	
}



static int ddos_detect(struct rte_mbuf *pkt) {

	static char flag = 0; // 1 ddos, 0 no attack

	uint8_t *msg = rte_pktmbuf_mtod(pkt, uint8_t * );
	uint32_t set_bits = count_bit(msg, pkt->buf_len);

	uint32_t tot_bits = pkt->buf_len * 8;

	p_setbits[pkt_idx % CAPTURE_WINDOWS] = set_bits;
	p_totbits[pkt_idx % CAPTURE_WINDOWS] = tot_bits;
	p_entropy[pkt_idx % CAPTURE_WINDOWS] = ddos_entropy(set_bits, tot_bits);

	//printf("\n %u/%u, E(%f)\n", set_bits, tot_bits, p_entropy[pkt_idx % CAPTURE_WINDOWS]);
	if (pkt_idx >= CAPTURE_WINDOWS) {

		int i = 0;
		uint32_t total_set = 0, total_bit = 0;
		double sum_entropy = 0.0;
		
		for (i = 0;i < CAPTURE_WINDOWS;i ++) {
			total_set += p_setbits[i]; // set_bits
			total_bit += p_totbits[i]; // count_bits
			sum_entropy += p_entropy[i];
		}

		double entropy = ddos_entropy(total_set, total_bit);

	// nan -->  
		//printf("%u/%u Entropy(%f), Total_Entropy(%f)\n", total_set, total_bit, sum_entropy, entropy);
		if (tresh <  sum_entropy - entropy) { // ddos attack

			if (!flag) { // detect
				// 
				rte_exit(EXIT_FAILURE, "ddos attack !!! Entropy(%f) < Total_Entropy(%f)\n", 
					entropy, sum_entropy);

			}

			flag = 1;

		} else {

			if (flag) { //
				
				printf( "no new !!! Entropy(%f) < Total_Entropy(%f)\n", 
					entropy, sum_entropy);
			}

			flag = 0;

		}
		
		// sum(p_entropy[i])
		// ddos_entropy(sum(set_bits), sum(tot_bits));

		pkt_idx = (pkt_idx+1) % CAPTURE_WINDOWS + CAPTURE_WINDOWS;
	} else {
		pkt_idx ++;
	}
	

	return 0;
	
}



#endif


int main(int argc, char *argv[]) {

	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
		
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

#if ENABLE_KNI_APP

	if (-1 == rte_kni_init(gDpdkPortId)) {
		rte_exit(EXIT_FAILURE, "kni init failed\n");
	}
	ng_init_port(mbuf_pool);
	// kni_alloc
	global_kni = ng_alloc_kni(mbuf_pool);

#else	
	ng_init_port(mbuf_pool);

#endif


	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

#if ENABLE_TIMER

	rte_timer_subsystem_init();

	struct rte_timer arp_timer;
	rte_timer_init(&arp_timer);

	uint64_t hz = rte_get_timer_hz();
	unsigned lcore_id = rte_lcore_id();
	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

#endif

#if ENABLE_RINGBUFFER

	struct inout_ring *ring = ringInstance();
	if (ring == NULL) {
		rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
	}

	if (ring->in == NULL) {
		ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}
	if (ring->out == NULL) {
		ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	}

#endif

#if ENABLE_MULTHREAD

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

#endif

#if ENABLE_UDP_APP

	lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
	rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

#endif

#if ENABLE_TCP_APP
	
		lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
		rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);
	
#endif


	while (1) {

		// rx
		struct rte_mbuf *rx[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (num_recvd > 0) {
#if ENABLE_DDOS_DETECT
		
			unsigned i = 0;
			for (i = 0;i < num_recvd;i ++) {
				ddos_detect(rx[i]);
			}
#endif
			rte_ring_sp_enqueue_burst(ring->in, (void**)rx, num_recvd, NULL);
		}

		
		// tx
		struct rte_mbuf *tx[BURST_SIZE];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {

			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

			unsigned i = 0;
			for (i = 0;i < nb_tx;i ++) {
				rte_pktmbuf_free(tx[i]);
			}
			
		}
		


#if ENABLE_TIMER

		static uint64_t prev_tsc = 0, cur_tsc;
		uint64_t diff_tsc;

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}

#endif


	}

}




