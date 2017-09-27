/*
 *	Definitions for the QUIC code.
 */
#ifndef _QUIC_H
#define _QUIC_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <linux/math64.h>
//#include <net/ip6_checksum.h>
#define DATA	10
#define SYN 	13	
#define SYN_REP	14	
#define ACK	15
#define NACK	16
#define DELTA	17
#define END	99


//QUIC buffer size limit
#define QUIC_MAX_SENDBUF 64 

//As per RFC6298 at https://tools.ietf.org/html/rfc6298
#define QUIC_RTO_MAX		((unsigned) (120*HZ))
#define QUIC_DEL_ACK		msecs_to_jiffies(40)  //As per https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_MRG/1.3/html/Realtime_Tuning_Guide/sect-Realtime_Tuning_Guide-General_System_Tuning-Reducing_the_TCP_delayed_ack_timeout.html

//As per QUIC Doc at https://tools.ietf.org/html/draft-tsvwg-quic-loss-recovery-01 (section 3.2)
#define QUIC_RTO_MIN		((unsigned) (HZ/5))
#define RESEND_THRESHOLD 3

//AS per RFC 5681 on congestion control
#define IW 		2


#define QUIC_SKB_CB(__skb)       ((struct quic_skb_cb *)&((__skb)->cb[0]))
#define QUIC_TIMESTAMP   	 ((__u32)(jiffies))

//TCP Cubic

#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)
#define HYSTART_DELAY_MAX	(16U<<3)
#define HYSTART_DELAY_THRESH(x)	clamp(x, HYSTART_DELAY_MIN, HYSTART_DELAY_MAX)


extern struct proto 		quic_prot;
extern struct udp_table		quic_table;

enum timer_flags {
        QUIC_RTO_TLP_TIMER_DEFERRED,  /* quic_rto_tlp_timer() found socket was owned */
        QUIC_DEL_ACK_TIMER_DEFERRED,  /* quic_rto_tlp_timer() found socket was owned */
        QUIC_EARLY_RETRANS_TIMER_DEFERRED,  /* quic_rto_tlp_timer() found socket was owned */
        QUIC_HSHAKE_LOSS_TIMER_DEFERRED  /* tcp_write_timer() found socket was owned */
        //TCP_DELACK_TIMER_DEFERRED, /* tcp_delack_timer() found socket was owned */
        //TCP_MTU_REDUCED_DEFERRED,  /* tcp_v{4|6}_err() could not call
        //                            * tcp_v{4|6}_mtu_reduced()
        //                            */
};

enum state {
        QUIC_CA_Open,  
	QUIC_Loss  
};


struct quichdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
	__u8	ver:1,
		pres:1,
		div:1,
		cid:1,
		pnum:2,
		mpath:1,
		uused:1;
	__be64	conn_id;
	__be32	version;
	__be32	offset;
	__be32	sequence;
	__be32 	type;		//To put this in switch case, Need to have an END tag
};

struct quic_skb_cb {
	//Specific to UDP
        union {
             struct inet_skb_parm    h4;
#if IS_ENABLED(CONFIG_IPV6)
             struct inet6_skb_parm   h6;
#endif
        } header;
        __u16   cscov;
        __u8    partial_cov;

	//Specific to QUIC
	__u8	ver:1,
		pres:1,
		div:1,
		cid:1,
		pnum:2,
		mpath:1,
		uused:1;
	__be32	offset;
	__be32	sequence;
	__be32 	type;		//Last field, First frame type in the datagram
	__u32	timestamp;		//Calculate RTT
	__u32	missing_reports;		//NACK count
};

/*************** Frame type ***********************
 Data	10
 SYN 	13	
 ACK	14
 */


struct syn_cookie_headless {
	//__be32 id;		// Right now, setting it to 13 (Just a random choice)
	//__be64 cookie;
	__be32 cookie;
};

struct syn_cookie {
	__be32 id;		// Right now, setting it to 13 (Just a random choice)
	__be32 cookie;
};

struct ack_frame {
	__be32 id;		// Right now, setting it to 14 (Just a random choice)
	__be32 offset;
//	__be32 sequence;
};

struct quic_bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point from the beginning of the current epoch */
	u32	delay_min;	/* min delay (msec << 3) */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
#define ACK_RATIO_SHIFT	4
#define ACK_RATIO_LIMIT (32u << ACK_RATIO_SHIFT)
	u16	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
};


struct quic_sock {
	/* inet_sock has to be the first member */
	struct inet_sock inet;
#define udp_port_hash		inet.sk.__sk_common.skc_u16hashes[0]
#define udp_portaddr_hash	inet.sk.__sk_common.skc_u16hashes[1]
#define udp_portaddr_node	inet.sk.__sk_common.skc_portaddr_node
	int		 pending;	/* Any pending frames ? */
	unsigned int	 corkflag;	/* Cork is required */
  	__u16		 encap_type;	/* Is this an Encapsulation socket? */
	/*
	 * Following member retains the information to create a UDP header
	 * when the socket is uncorked.
	 */
	__u16		 len;		/* total length of pending frames */
	/*
	 * Fields specific to UDP-Lite.
	 */
	__u16		 pcslen;
	__u16		 pcrlen;
/* indicator bits used by pcflag: */
#define UDPLITE_BIT      0x1  		/* set by udplite proto init function */
#define UDPLITE_SEND_CC  0x2  		/* set via udplite setsockopt         */
#define UDPLITE_RECV_CC  0x4		/* set via udplite setsocktopt        */
	__u8		 pcflag;        /* marks socket as UDP-Lite if > 0    */
	__u8		 unused[3];
	/*
	 * For encapsulation sockets.
	 */
	int (*encap_rcv)(struct sock *sk, struct sk_buff *skb);
	void (*encap_destroy)(struct sock *sk);


	__be64		conn_id;
	__be64 		syn_cookie;


	// Send/Receive Queue variables
	// *********************************
	
	bool	 	syn_acked;		//Check if the SYN reply has been acked
	__be32		syn_offset;

	__be32		first_unack;		//Head of send window
	__be32		send_next;		//Last sent and unacked datagram + 1
	__be32		send_next_sequence;		//Last sent and unacked datagram + 1

	__be32		rcv_next;		//Start of receive window

	__be32		highest_rcv;		//Highest received packet offset at receiver
	__be32		highest_rcv_sequence;	//Highest received packet sequence at receiver
	__u32		highest_rcv_time;

	__be32		highest_ack;		//Highest acked packet at sender
	__be32		highest_ack_sequence;	//Highest acked packet at sender
	__u32		highest_ack_rtt;

	unsigned int		packets_out;	//Keep account
	unsigned int		nacked_in_q;
	struct sk_buff		*last_sent;	//Keep track of the last sent packet

	//struct sk_buff_head     send_buffer;
	//struct sk_buff_head     rcv_buffer;

	// Timer Variables
	// ***********************************
	unsigned long   	timer_flags;

	struct timer_list	quic_hshake_loss_timer;
	__u32			hshake_loss_timeout;

	struct timer_list	quic_rto_tlp_timer;
	unsigned int		tlp_out;

	struct timer_list	quic_del_ack_timer;

	struct timer_list	quic_early_retrans_timer;

	unsigned int		retransmits;	//For Backoff

	unsigned long		tlp_rto_time;
	unsigned long		hshake_loss_time;
	unsigned long		del_ack_time;
	unsigned long		early_retransmit_time;

	u32     		srtt;           /* smoothed round trip time << 3        */
	u32     		mdev;           /* medium deviation                     */
	u32     		mdev_max;       /* maximal mdev for the last rtt period */
	u32     		rttvar;         /* smoothed mdev_max                    */
	u32     		rtt_seq;        /* sequence number to update rttvar     */

	u32			rto;
	unsigned int		number_rto_packets;

	bool			first_rtt;
	bool			first_ack;
	bool			sending;
	bool			server;	//This socket is the server (or receiver)

	//Congestion control
	unsigned long	 	ca_state;
	unsigned int		cwnd;
	unsigned int		cwnd_cnt;
	unsigned int		ssthresh;
	struct quic_bictcp		ca;

	int fast_convergence;
	int beta;	/* = 717/1024 (BICTCP_BETA_SCALE) */
	int initial_ssthresh;
	int bic_scale;
	int tcp_friendliness;
	
	int hystart;
	int hystart_detect;
	int hystart_low_window;
	int hystart_ack_delta;
	
	u32 cube_rtt_scale;
	u32 beta_scale;
	u64 cube_factor;

};

static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct quichdr *quic_hdr(const struct sk_buff *skb)
{
	return (struct quichdr *)skb_transport_header(skb);
}

static inline char *data_begin(const struct sk_buff *skb)
{
	return (char *)(skb_transport_header(skb) + sizeof(struct quichdr));
}

static inline __wsum quic_csum(struct sk_buff *skb)
{
	__wsum csum = csum_partial(skb_transport_header(skb),
				   sizeof(struct quichdr), skb->csum);

	for (skb = skb_shinfo(skb)->frag_list; skb; skb = skb->next) {
		csum = csum_add(csum, skb->csum);
	}
	return csum;
}

static inline __sum16 __quic_lib_checksum_complete(struct sk_buff *skb)
{
	return __skb_checksum_complete_head(skb, QUIC_SKB_CB(skb)->cscov);
}

static inline int quic_lib_checksum_complete(struct sk_buff *skb)
{
	return !skb_csum_unnecessary(skb) &&
		__quic_lib_checksum_complete(skb);
}


int quic_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len);
int quic_push_pending_frames(struct sock *sk);

int quic_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int noblock, int flags, int *addr_len);
int __quic4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
		   int proto);
int quic_queue_rcv_skb(struct sock *sk, struct sk_buff *skb);
int __quic4_lib_mcast_deliver(struct net *net, struct sk_buff *skb,
				    struct quichdr  *qh,
				    __be32 saddr, __be32 daddr,
				    struct udp_table *udptable);
inline int quic4_csum_init(struct sk_buff *skb, struct quichdr *qh,
				 int proto);

int quic_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len);
int quic_send_connect(struct sock *sk, struct sockaddr *uaddr);

void quic4_register(void);

int quic_sendpage(struct sock *sk, struct page *page, int offset,
		 size_t size, int flags);
int quic_finish_send_skb(struct sk_buff *skb, int clone, int retransmit);
int try_send_packets(struct sock *sk);
void retransmit_nacked(struct sock *sk, const unsigned int threshold);
int send_ack(struct sock *sk);

#endif	/* _QUIC_H */
