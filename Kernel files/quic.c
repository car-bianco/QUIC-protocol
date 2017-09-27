
#define pr_fmt(fmt) "QUIC: " fmt

#include <linux/export.h>
#include "udp_impl.h"
#include <net/tcp.h>
#include <net/secure_seq.h>
#include <net/quic.h>
#include <net/xfrm.h>
#include <net/icmp.h>
#include <net/sock.h>
#include <trace/events/skb.h>
//same kind of table as in UDP is kept
struct udp_table 	quic_table __read_mostly;
EXPORT_SYMBOL(quic_table);
//see __quic4_lib_rcv - handler at reception
static int quic_rcv(struct sk_buff *skb)
{
	return __quic4_lib_rcv(skb, &quic_table, IPPROTO_QUIC);
}
//default error handler is the same as in UDP
static void quic_err(struct sk_buff *skb, u32 info)
{
	__udp4_lib_err(skb, info, &quic_table);
}
//struct is defined, needed for add_protocol function
//exact same stuff as in /af_inet.c
static const struct net_protocol quic_protocol = {
	.handler	= quic_rcv,
	.err_handler	= quic_err,
	.no_policy	= 1, //default value: no need to check for policy constraints
	.netns_ok	= 1, //default value: protocol is aware of network namespaces (if this field equals 0, nothing will work)
};

//Recalculating threshold after a loss event
static u32 bictcp_recalc_ssthresh(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk); /* see quic.h - finally found it */
	struct quic_bictcp *ca = &qp->ca; /* see thesis for complete definition (...) */

	ca->epoch_start = 0;	/* end of epoch, beginning of new one */

//special case considered: fast convergence
	/* Wmax and fast convergence */
	if (qp->cwnd < ca->last_max_cwnd && qp->fast_convergence)
		ca->last_max_cwnd = (qp->cwnd * (BICTCP_BETA_SCALE + qp->beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = qp->cwnd;
//save previous congestion window
	ca->loss_cwnd = qp->cwnd;
//1024 as scale factor for beta calculation
	return max((qp->cwnd * qp->beta) / BICTCP_BETA_SCALE, 2U); //2 as smallest threshold
}



// ****   Timer functions
// *****************************************************************************************
//stop early retransmit timer and clear it
static inline void quic_clear_early_retrans_timer
			(struct sock *sk
			// , int what
			 ){
	struct quic_sock *qp = quic_sk(sk);

	sk_stop_timer(sk, &qp->quic_early_retrans_timer);	
	qp->early_retransmit_time = 0;

	printk("Cleared the early retransmit timer\n");
}
//reset early retransmit timer
static inline void quic_reset_early_retrans_timer
			(struct sock *sk,
		//	 int what,
			 unsigned long when){
	struct quic_sock *qp = quic_sk(sk);
//jiffies:= number of system clocks since it has booted!
	qp->early_retransmit_time = jiffies + when;
	sk_reset_timer(sk, &qp->quic_early_retrans_timer, qp->early_retransmit_time);
	printk("Set the early retransmit timer\n");
}

//handler for early retransmit timer (what if this timer expires?)
/* this timer is set if a packet is NACKed and the receiver has already received the largest
sent packet. It's meant to prevent a RTO from the loss of just one packet */
void quic_early_retrans_timer_handler(struct sock *sk){
	struct quic_sock *qp = quic_sk(sk);

	//If the timeout has not yet happened
	if (time_after(qp->early_retransmit_time, jiffies)) {
		sk_reset_timer(sk, &qp->quic_early_retrans_timer, qp->early_retransmit_time);
		goto out;
	}
//TODO: goto? in 2017? WHY?
	//Do stuff
	qp->nacked_in_q = 0;
	retransmit_nacked(sk, 0);		
	//retransmit not acknowledged packets immediately -> early retransmit!
out:	
	sk_mem_reclaim(sk);
}


static void quic_early_retrans_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		quic_early_retrans_timer_handler(sk);
	} else {
		printk("/* delegate our work to quic_release_cb() */\n");
		if (!test_and_set_bit(QUIC_EARLY_RETRANS_TIMER_DEFERRED, &quic_sk(sk)->timer_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}


/* Delayed Acknowledgement Timer: used to delay the transmission of ACKs to prevent packet drops on
network interfaces. Instant ACKs are sent for every second packet as well as for out-of-order packets */

//stop delayed acknowledgement timer and clear it
static inline void quic_clear_del_ack_timer
			(struct sock *sk
			// , int what
			 ){
	struct quic_sock *qp = quic_sk(sk);

	sk_stop_timer(sk, &qp->quic_del_ack_timer);	
	qp->del_ack_time = 0;

	printk("Cleared the DEL_ACK timer\n");
}
//reset delayed acknowledgement timer
static inline void quic_reset_del_ack_timer
			(struct sock *sk,
		//	 int what,
			 unsigned long when){
	struct quic_sock *qp = quic_sk(sk);

	qp->del_ack_time = jiffies + when;
	sk_reset_timer(sk, &qp->quic_del_ack_timer, qp->del_ack_time);
}

//if this times our, then send the acknowledgment
void quic_del_ack_timer_handler(struct sock *sk){
	struct quic_sock *qp = quic_sk(sk);

	//If the timeout has not yet happened
	if (time_after(qp->del_ack_time, jiffies)) {
		sk_reset_timer(sk, &qp->quic_del_ack_timer, qp->del_ack_time);
		goto out;
	}

	send_ack(sk);
out:	
	sk_mem_reclaim(sk);
}


static void quic_del_ack_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		quic_del_ack_timer_handler(sk);
	} else {
		printk("/* delegate our work to quic_release_cb() */\n");
		if (!test_and_set_bit(QUIC_DEL_ACK_TIMER_DEFERRED, &quic_sk(sk)->timer_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}
/* Retransmission TimeOut and Tail Loss Probe timers (TODO: google it!). TLP set with a value depending on the 
number of transmitted but unACKed packets */

//stop RTO/TLP timer and clear it
static inline void quic_clear_rto_tlp_timer
			(struct sock *sk
			// , int what
			 ){
	struct quic_sock *qp = quic_sk(sk);

	sk_stop_timer(sk, &qp->quic_rto_tlp_timer);	
	qp->retransmits = 0;    //clear number of retransmits
	qp->tlp_out = 0;        //number of times the TLP timer has expired
	qp->tlp_rto_time = 0;

	printk("Cleared the RTO/TLP timer\n");
}

//reset RTO/TLP timer
static inline void quic_reset_rto_tlp_timer
			(struct sock *sk,
		//	 int what,
			 unsigned long when){
	struct quic_sock *qp = quic_sk(sk);

	qp->tlp_rto_time = jiffies + when;

	sk_reset_timer(sk, &qp->quic_rto_tlp_timer, qp->tlp_rto_time);
//like in thesis: TLP becomes RTO if expired twice or more!
	if(qp->tlp_out < 2){
		printk("Set the TLP timer to %lums for TLP number %u\n", when, qp->tlp_out);
	}else{
		printk("Set the RTO timer to %lums\n", when);
	}
}

//when the TLP timer expires, a single packet is resent as probe and the timer is reset as a TLP or RTO timer
void quic_rto_tlp_timer_handler(struct sock *sk){
	struct quic_sock *qp = quic_sk(sk);
	struct sk_buff *skb;
	u32 rto;
	int i;

	//If the timeout has not yet happened
	if (time_after(qp->tlp_rto_time, jiffies)) {
		sk_reset_timer(sk, &qp->quic_rto_tlp_timer, qp->tlp_rto_time);
		goto out;
	}


	//Do stuff
	//tlp_out < 2 -> still TLP timer
	if(qp->tlp_out < 2){
		if(skb_queue_empty(&sk->sk_write_queue)){
				printk("Error: TLP timer fired when send queue empty\n"); //there's an error: TLP timer shouldn't fire!
				goto out;
		}
		//function for actual packet sending -> send a packet immediately as probe!
		quic_finish_send_skb(skb_peek(&sk->sk_write_queue), 1, 1);
		qp->tlp_out++;
		printk("TLP timer expired at %lums, number of TLPs sent = %u\n", jiffies, qp->tlp_out);
		//Set the timer again, using formulas 3.4 to 3.5
		if(qp->tlp_out == 2){
			quic_reset_rto_tlp_timer(sk, qp->rto);  //timer has expired twice now -> RTO
		}else if(qp->tlp_out == 1){
			if(qp->packets_out == 1){               //only one packet in flight
				quic_reset_rto_tlp_timer(sk, max( 1.5*(qp->srtt>>3)+QUIC_DEL_ACK,  2*(qp->srtt>>3)));
			}else if(qp->packets_out > 1){          //multiple packets in flight
				quic_reset_rto_tlp_timer(sk, max( msecs_to_jiffies(10),  2*(qp->srtt>>3)));
			}
		}else{
			printk("Error: Invalid qp->tlp_out value of %u\n", qp->tlp_out);
		}
        //already failed twice
	} else if(qp->tlp_out == 2){
		qp->retransmits++;
		qp->number_rto_packets = 0;
		printk("RTO Timer expired at %lums, retransmits = %u\n", jiffies, qp->retransmits);
		if(qp->rto > (QUIC_RTO_MAX/2)){
			rto = QUIC_RTO_MAX;
		}else{
			rto = qp->rto;
			for(i = qp->retransmits; i>0; i--){
				rto *= 2; //TODO: Shift here?
				if(rto > QUIC_RTO_MAX)
					break;
			}
			if(rto > QUIC_RTO_MAX)
				rto = QUIC_RTO_MAX; //RFC6298
		}
		quic_reset_rto_tlp_timer(sk, rto);
        
		if(skb_queue_empty(&sk->sk_write_queue)){
				printk("Error: RTO timer fired when send queue empty\n");
				goto out;
		}
        //loss event -> reset congestion window and recalculate threshold
		qp->ssthresh = bictcp_recalc_ssthresh(sk);
		qp->cwnd = 1;
		qp->ca_state = QUIC_CA_Loss;
        //send next, or next two, packets (remember: every second packet gets ACKed if everything goes well)
		skb = skb_peek(&sk->sk_write_queue);
		quic_finish_send_skb(skb, 1, 1);
		qp->number_rto_packets = 1;
		if(skb_queue_len(&sk->sk_write_queue) > 1){
			quic_finish_send_skb(skb->next, 1, 1);
			qp->number_rto_packets = 2;
		}

	}else{
		printk("Unforseen condition in quic_rto_tlp_timer_handler(), tlp_out = %u\n", qp->tlp_out);
	}

out:	
	sk_mem_reclaim(sk);
}
/*  this function, as well as the similar ones for the other timers, checks whether the socket is already locked,
    in which case it has to wait until it is released. After that, the "actual" handler function is called */
static void quic_rto_tlp_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		quic_rto_tlp_timer_handler(sk);
	} else {
		printk("/* delegate our work to quic_release_cb() */\n");
		if (!test_and_set_bit(QUIC_RTO_TLP_TIMER_DEFERRED, &quic_sk(sk)->timer_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}




// Hshake and Loss Timer
/* 1.   if SYN has been sent, retransmit the hello packet for the client if a reply hasn't been received
        in a specified time
   2.   if socket connected, implement fast retransmit - update congestion window and retransmit NACKed 
        packets, if there's any */

//stop handshake and loss timer and clear it
static inline void quic_clear_hshake_loss_timer
			(struct sock *sk
			// , int what
			 ){
	struct quic_sock *qp = quic_sk(sk);

	sk_stop_timer(sk, &qp->quic_hshake_loss_timer);	
	qp->retransmits = 0;        //here also - reset number of retransmission
	qp->hshake_loss_time = 0;

	printk("Cleared the hshake/loss timer\n");
}

//reset handshake and loss timer
static inline void quic_reset_hshake_loss_timer
			(struct sock *sk,
		//	 int what,
			 unsigned long when){
	struct quic_sock *qp = quic_sk(sk);

	qp->hshake_loss_time = jiffies + when;

	sk_reset_timer(sk, &qp->quic_hshake_loss_timer, qp->hshake_loss_time);
}

//this function decides what to do based on the socket state - if connected or not
void quic_hshake_loss_timer_handler(struct sock *sk){
	struct quic_sock *qp = quic_sk(sk);
	u32 rto;
	int i;

	//If the timeout has not yet happened, reset timer and quit (quite uninteresting...)
	if (time_after(qp->hshake_loss_time, jiffies)) {
		sk_reset_timer(sk, &qp->quic_hshake_loss_timer, qp->hshake_loss_time);
		goto out;
	}

    //switch: check socket state
	switch(sk->sk_state){
	case TCP_SYN_SENT:          //connection is being established -> HANDSHAKE timer
	
		if(skb_queue_empty(&sk->sk_write_queue)){
			printk("Error: Nothing to send on Handshake timer expiration\n");
			goto out;
		}
    //retransmit the hello packet for the client
		qp->retransmits++;
		rto = 1.5*((qp->srtt)>>3);
		for(i = qp->retransmits; i>0; i--){
			rto *= 2;
			if(rto > QUIC_RTO_MAX)
				break;
		}
		if(rto > QUIC_RTO_MAX)
			rto = QUIC_RTO_MAX;

		quic_reset_hshake_loss_timer(sk, rto);

		printk("QUIC handshake Timer expired, resetting it to %ums\n", rto);

		quic_finish_send_skb(skb_peek(&sk->sk_write_queue), 1, 1);
	
		//Need to implement Backoff

		goto out;



	case TCP_ESTABLISHED:       //connection has already been established -> LOSS timer
	      	//Follow the Retransmit strategy at
	      	// https://tools.ietf.org/html/draft-tsvwg-quic-loss-recovery-01
		
		/*qp->packets_out = 0;
		qp->last_sent = NULL;*/

	      	//Report loss to congestion controller
		qp->cwnd = qp->ssthresh = bictcp_recalc_ssthresh(sk);
		qp->ca_state = QUIC_CA_Recovery;
	      
		printk("QUIC Loss Timer expired at %lu, New CWND and SSThreshold = %u\n", jiffies, qp->cwnd);
	      	//Retransmit as many as allowed
		//try_send_packets(sk);
		qp->nacked_in_q = 0;
		retransmit_nacked(sk, RESEND_THRESHOLD);

		//Retransmit => Retransmit the packets
	}

out:	
	sk_mem_reclaim(sk);
}

static void quic_hshake_loss_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;

	bh_lock_sock(sk);
	if (!sock_owned_by_user(sk)) {
		quic_hshake_loss_timer_handler(sk);
	} else {
		printk("/* delegate our work to quic_release_cb() */\n");
		if (!test_and_set_bit(QUIC_HSHAKE_LOSS_TIMER_DEFERRED, &quic_sk(sk)->timer_flags))
			sock_hold(sk);
	}
	bh_unlock_sock(sk);
	sock_put(sk);
}

//initialize all four timers at the beginning (handshake/loss, RTO/TLP, delayed ACK, early retransmit)

void quic_init_xmit_timers(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);

	setup_timer(&qp->quic_hshake_loss_timer, &quic_hshake_loss_timer,
		(unsigned long)sk);
	setup_timer(&qp->quic_rto_tlp_timer, &quic_rto_tlp_timer,
		(unsigned long)sk);
	setup_timer(&qp->quic_del_ack_timer, &quic_del_ack_timer,
		(unsigned long)sk);
	setup_timer(&qp->quic_early_retrans_timer, &quic_early_retrans_timer,
		(unsigned long)sk);
}
/*  This function checks the timer flags and calls handler functions for those timers which 
    had fired but couldn't run! */
void quic_release_cb(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);
	unsigned long  	flags;
	flags = qp->timer_flags;
	memset(&qp->timer_flags, 0, sizeof(qp->timer_flags));

	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	sock_release_ownership(sk);

	if (flags & (1UL << QUIC_HSHAKE_LOSS_TIMER_DEFERRED)) {
		quic_hshake_loss_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & (1UL << QUIC_DEL_ACK_TIMER_DEFERRED)) {
		quic_del_ack_timer_handler(sk);
		__sock_put(sk);
	}
	if (flags & (1UL << QUIC_RTO_TLP_TIMER_DEFERRED)) {
		quic_rto_tlp_timer_handler(sk);
		__sock_put(sk);
	}
	

}
//EXPORT_SYMBOL(quic_release_cb);


//****************  Congestion control
////*****************************************************************************************


//void increase_cwnd(struct sock *sk, unsigned int count){
//	struct quic_sock *qp = quic_sk(sk);
//
//	if(qp->cwnd < qp->ssthresh){	//Slow start
//		if(qp->cwnd < (UINT_MAX/2)){
//			qp->cwnd += count;
//		}else{
//			qp->cwnd = UINT_MAX;
//		}
//		printk("In slow start, set the CWND to %u, SSTHRESH = %u\n", qp->cwnd, qp->ssthresh);
//	}else{
//		if(qp->cwnd < UINT_MAX){
//			qp->cwnd++;
//		}else{
//		}
//		printk("In congestion avoidance, set the CWND to %u, SSTHRESH = %u\n", qp->cwnd, qp->ssthresh);
//	}
//
//}

//CONGESTION CONTROL: QUIC uses the TCP Cubic congestion control algorithm

//reset control structure
static inline void bictcp_reset(struct quic_bictcp *ca)
{
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->found = 0;
}
//convert current time from boot (jiffies) to msecs
static inline u32 bictcp_clock(void)
{
	return jiffies_to_msecs(jiffies);
}
//resetting the whole algorithm(?)
static inline void bictcp_hystart_reset(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);
	struct quic_bictcp *ca = &qp->ca;

	ca->round_start = ca->last_ack = bictcp_clock();    
	ca->end_seq = qp->send_next;
	ca->curr_rtt = 0;
	ca->sample_cnt = 0;
}

//initializing TCP Cubic algorithm
static void bictcp_init(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);
	struct quic_bictcp *ca = &qp->ca;

	bictcp_reset(ca);
	ca->loss_cwnd = 0;

	if (qp->hystart)
		bictcp_hystart_reset(sk);

	if (!qp->hystart && qp->initial_ssthresh)
		qp->ssthresh = qp->initial_ssthresh;
}


/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 * I guess this comes from some website...what do those values stand for?
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}


/*
 * Compute congestion window to use. (update congestion window after each positive ACK)
 */
static inline void bictcp_update(struct sock *sk, struct quic_bictcp *ca, u32 cwnd)
{
	struct quic_sock *qp = quic_sk(sk);
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	ca->ack_cnt++;	/* count the number of ACKs */

	if (ca->last_cwnd == cwnd &&
	    (s32)(jiffies - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = jiffies;

	if (ca->epoch_start == 0) {     /* epoch has been ended (see in the first lines...) */
		ca->epoch_start = jiffies;	/* record the beginning of an epoch */
		ca->ack_cnt = 1;			/* start counting (first ACK) */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(qp->cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(jiffies - ca->epoch_start);
	t += msecs_to_jiffies(ca->delay_min >> 3);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);
    /* offs = |t-K| (abs. value) */
	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (qp->cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                                	/* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                                	/* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	/* special case -> no information about available bandwidth (algorithm has just been started)
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

	/* TCP Friendly (???) */
	if (qp->tcp_friendliness) {
		u32 scale = qp->beta_scale;
		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd){	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}
    
	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;            //minimum count = 1
}

//tells if congestion window has already been filled

bool quic_is_cwnd_limited(const struct sock *sk, u32 in_flight)
{
	struct quic_sock *qp = quic_sk(sk);
        //u32 left;

        if (in_flight >= qp->cwnd){
                return true;
	}else{
		return false;
	}

        //left = qp->cwnd - in_flight;
        //if (sk_can_gso(sk) &&
        //    left * sysctl_tcp_tso_win_divisor < tp->snd_cwnd &&
        //    left * tp->mss_cache < sk->sk_gso_max_size &&
        //    left < sk->sk_gso_max_segs)
        //        return true;
        //return left <= tcp_max_tso_deferred_mss(tp);
}
//slow start as in normal TCP congestion control, until a threshold is reached
int quic_slow_start(struct sock *sk, u32 acked)
{
    //each ACKed packet leads to cwnd increase by size of ACK
	struct quic_sock *qp = quic_sk(sk);
        u64 cwnd = (u64)qp->cwnd + (u64)acked;

	//If the above addition results in crossing the threshhold
        if (cwnd > (u64)qp->ssthresh)
                cwnd = (u64)qp->ssthresh;
	
	qp->cwnd = (u32) min((u64) cwnd, (u64) UINT_MAX);
        acked -= cwnd - qp->cwnd;                       //if something has been left unacked due to overflow
        return acked;
}
//Congestion avoidance: Additive increase
void quic_cong_avoid_ai(struct sock *sk, u32 w)
{
	struct quic_sock *qp = quic_sk(sk);
    //each ACKed packet leads to cwnd incerase by 1, until UINT_MAX reached
	printk("cwnd_cnt = %u, cnt needed = %u\n", qp->cwnd_cnt, w);
        if (qp->cwnd_cnt >= w) {
                if (qp->cwnd < UINT_MAX)
                        qp->cwnd++;
                qp->cwnd_cnt = 0;
        } else {
                qp->cwnd_cnt++;
        }
}
//calls slow start and congestion avoidance functions as needed
static void bictcp_cong_avoid(struct sock *sk, u32 ack, u32 acked,
			      u32 in_flight)
{
	struct quic_sock *qp = quic_sk(sk);
	struct quic_bictcp *ca = &qp->ca;
    //no need to increment the congestion window!
	if (!quic_is_cwnd_limited(sk, in_flight)){
		printk("bictcp_cong_avoid(): Not limited by congestion window\n");
		return;
	}

	if (qp->cwnd < qp->ssthresh) {
		printk("bictcp_cong_avoid(): In slow start\n");
		if (qp->hystart && (ack > ca->end_seq))         //checks if a reset is necessary
			bictcp_hystart_reset(sk);
		quic_slow_start(sk, acked);
	} else {
		printk("bictcp_cong_avoid(): In Congestion avoidance\n");
		bictcp_update(sk, ca, qp->cwnd);                //Cubic TCP update
		quic_cong_avoid_ai(sk, ca->cnt);
	}

}
/*  Returns maximum of actual congestion window and congestion window at last loss. Used if a packet other than 
    the one sent after RTO is acked (i.e. things have unexpectedly gone well after we had given up hope) */
static u32 bictcp_undo_cwnd(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);
	struct quic_bictcp *ca = &qp->ca;

	return max(qp->cwnd, ca->loss_cwnd);
}


//HYSTART = TCP Cubic slow start algorithm. Two heuristics to exit slow start before losses start to occur.
static void hystart_update(struct sock *sk, u32 delay)
{
	struct quic_sock *qp = quic_sk(sk);
	struct quic_bictcp *ca = &qp->ca;

	if (!(ca->found & qp->hystart_detect)) {
		u32 now = bictcp_clock();

		/* first detection parameter - ack-train detection */
		if ((s32)(now - ca->last_ack) <= qp->hystart_ack_delta) {
			ca->last_ack = now;
			if ((s32)(now - ca->round_start) > ca->delay_min >> 4)
				ca->found |= HYSTART_ACK_TRAIN;
		}

		/* obtain the minimum delay of more than sampling packets */
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			if (ca->curr_rtt == 0 || ca->curr_rtt > delay)
				ca->curr_rtt = delay;

			ca->sample_cnt++;
		} else {
			if (ca->curr_rtt > ca->delay_min +
			    HYSTART_DELAY_THRESH(ca->delay_min>>4))
				ca->found |= HYSTART_DELAY;
		}
		/*
		 * Either one of two conditions are met,
		 * we exit from slow start immediately.
		 */
		if (ca->found & qp->hystart_detect)
			qp->ssthresh = qp->cwnd;
	}
}


//Called when new packets have been acked
static void bictcp_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct quic_sock *qp = quic_sk(sk);
	struct quic_bictcp *ca = &qp->ca;
	u32 delay;

	if (qp->ca_state == QUIC_CA_Open) {
		u32 ratio = ca->delayed_ack;

		ratio -= ca->delayed_ack >> ACK_RATIO_SHIFT;
		ratio += cnt;

		ca->delayed_ack = clamp(ratio, 1U, ACK_RATIO_LIMIT);
	}

	/* Some calls are for duplicates without timestamps */
	if (rtt < 0)
		return;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(jiffies - ca->epoch_start) < HZ)
		return;

	delay = (rtt << 3);
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (qp->hystart && qp->cwnd <= qp->ssthresh &&
	    qp->cwnd >= qp->hystart_low_window)
		hystart_update(sk, delay); //should we exit the slow start phase, even if we're under SSthresh?
}

//***********************************************************************************************
//***********************************************************************************************

static inline int quic_sk_init(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);

	sk->sk_state = TCP_CLOSE;
	printk("Set the QUIC socket state to TCP_CLOSE\n");
	__skb_queue_head_init(&sk->sk_write_queue);
	__skb_queue_head_init(&sk->quic_receive_queue);

	qp->first_unack = qp->send_next = qp->send_next_sequence = qp->rcv_next = qp->highest_rcv = 0;
	qp->syn_acked = 0;
	//memset(qp, 0, sizeof(struct quic_sock));
	//
	qp->packets_out = 0;
	qp->tlp_out = 0;
	qp->nacked_in_q = 0;
	qp->first_nack = 0;
	qp->sending = 0;
	qp->last_sent = NULL;
	qp->server = 0;
	
	//Init the Timers
	quic_init_xmit_timers(sk);
	memset(&qp->timer_flags, 0, sizeof(qp->timer_flags));

	//Set the initial RTO to 1s
	qp->rto = HZ;
	qp->srtt = 20<<3; //SRTT value is stored in multiple of 8
	qp->rttvar = 0;
	qp->mdev = 0;
	qp->mdev_max = 0;
	qp->rtt_seq = 0;
	qp->first_rtt = 1;
	qp->first_ack = 1;

	qp->number_rto_packets = 0;

	//Congestion Control************************************************************
	qp->cwnd = IW;
	qp->cwnd_cnt = 0;
	qp->ssthresh = UINT_MAX;

	qp->fast_convergence  = 1;
	qp->beta  = 717;	/* = 717/1024 (BICTCP_BETA_SCALE) */
	qp->initial_ssthresh = UINT_MAX;
	qp->bic_scale  = 41;
	qp->tcp_friendliness  = 1;
	
	qp->hystart  = 1;
	qp->hystart_detect  = HYSTART_ACK_TRAIN | HYSTART_DELAY;
	qp->hystart_low_window  = 16;
	qp->hystart_ack_delta  = 2;
    //initial congestion window is set to 2
	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

	qp->beta_scale = 8*(BICTCP_BETA_SCALE+qp->beta)/ 3 / (BICTCP_BETA_SCALE - qp->beta);

	qp->cube_rtt_scale = (qp->bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	qp->cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(qp->cube_factor, qp->bic_scale * 10);

	printk("HZ = %u\n, initial CWND = %u, SSTHRESH = %u\n", qp->rto, qp->cwnd, qp->ssthresh);
	
	return 0;

}

//timers are cleared, queue is emptied, state is changed to "TCP_CLOSE"; only after that, socket is released

static inline void quic_lib_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;


	quic_clear_hshake_loss_timer(sk);
	quic_clear_rto_tlp_timer(sk);
	quic_clear_del_ack_timer(sk);
	quic_clear_early_retrans_timer(sk);

	while(!skb_queue_empty(&sk->sk_write_queue)){
		skb = skb_peek(&sk->sk_write_queue);
		skb_unlink(skb, &sk->sk_write_queue);
		kfree_skb(skb);
	}
	printk("Emptied the send queue....");
	sk->sk_state = TCP_CLOSE;
	printk("Closing socket.........\n");

        sk_common_release(sk);
}
//the structures needed for the protocol are defined
//all "general" functions are connected either to functions defined in this module or to UDP functions
//(TCP builds on top of UDP)
struct proto 	quic_prot = {
	.name		   = "QUIC",
	.owner		   = THIS_MODULE,
	.close		   = quic_lib_close,
	.connect	   = quic_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.init		   = quic_sk_init,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = quic_sendmsg,
	.recvmsg	   = quic_recvmsg,
	//.sendpage	   = quic_sendpage,
	.backlog_rcv	   = quic_queue_rcv_skb,
	.release_cb	   = quic_release_cb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.get_port	   = udp_v4_get_port,
	.obj_size	   = sizeof(struct quic_sock), //equals size of the socket
	.slab_flags	   = SLAB_DESTROY_BY_RCU,
	.h.udp_table	   = &quic_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
	.clear_sk	   = sk_prot_clear_portaddr_nulls,
};
EXPORT_SYMBOL(quic_prot);
//structure for each socket type
static struct inet_protosw quic4_protosw = {
	.type		=  SOCK_DGRAM,                              //socket type
	.protocol	=  IPPROTO_QUIC,                            //(18) search entry for given socket
	.prot		=  &quic_prot,                              //set of functions which are specific to the IP protocol
	.ops		=  &inet_dgram_ops,                         //for socket-related systemcalls
	/* first, a function call from proto-ops is made, then the corresponding call from proto */
	.no_check	=  0,		/* must checksum (RFC 3828) */
	.flags		=  INET_PROTOSW_PERMANENT,                  //behavior cannot be overridden
};

#ifdef CONFIG_PROC_FS
/* important kernel data structure; needed for char driver to set up a connection */
static const struct file_operations quic_afinfo_seq_fops = {
	.owner    = THIS_MODULE,        //module that owns the structure (here: default value)
	.open     = udp_seq_open,       //first operation performed (not always required!) 
	.read     = seq_read,           //retrieve data
	.llseek   = seq_lseek,          //change current read/write position in a file
	.release  = seq_release_net     //invoked when the file structure is being released
};

static struct udp_seq_afinfo quic4_seq_afinfo = {
	.name		= "quic",
	.family		= AF_INET,
	.udp_table 	= &quic_table,              //QUIC runs on top of UDP - tables are the same
	.seq_fops	= &quic_afinfo_seq_fops,    //file operations already defined in the prev struct
	.seq_ops	= {
		.show		= udp4_seq_show,        //further operations
	},
};

static int __net_init quic4_proc_init_net(struct net *net)
{
	return udp_proc_register(net, &quic4_seq_afinfo);
}

static void __net_exit quic4_proc_exit_net(struct net *net)
{
	udp_proc_unregister(net, &quic4_seq_afinfo);
}
/* added for network namespaces specific data - init and exit for device/subsystem specific initialization and cleanup   */
static struct pernet_operations quic4_net_ops = {
	.init = quic4_proc_init_net,
	.exit = quic4_proc_exit_net,
};
//if it hasn't already been done - this function registers QUIC protocol with the network subsystem!
static __init int quic4_proc_init(void)
{
	return register_pernet_subsys(&quic4_net_ops);
}
#else
static inline int quic4_proc_init(void)
{
	return 0;
}
#endif
/* annotations like __init have no effect for normal computations - these macros are used to mark some initialized data as "initialization" functions, which means the kernel can free up memory resources afterwards */
void __init quic4_register(void)    
{
    //initializing UDP table
	udp_table_init(&quic_table, "QUIC");
	if (proto_register(&quic_prot, 1))              //register to Linux network subsystem
		goto out_register_err;
	printk("<7>\n Registered QUIC protocol\n");

	if (inet_add_protocol(&quic_protocol, IPPROTO_QUIC) < 0)    //protocol registers itself to net
		goto out_unregister_proto;
	printk("<7>\n added QUIC protocol to net\n");

	inet_register_protosw(&quic4_protosw); 

	if (quic4_proc_init())  //registers protocol within the network subsystem
		pr_err("%s: Cannot register /proc!\n", __func__);
	return;
//unnecessary gotos?
out_unregister_proto:
	proto_unregister(&quic_prot);                               //protocol has to unregister from Linux network subsystem if registration to protocol table fails!
out_register_err:
	pr_crit("%s: Can't add QUIC protocol\n", __func__);
}

/* final function which does the actual packet transmission, cloning the packet before sending to maintain a copy of them for retransmission, if necessary */
int quic_finish_send_skb(struct sk_buff *skb, int clone, int retransmit)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct quic_sock *qp = quic_sk(sk);
	struct quichdr *qh;
	struct quic_skb_cb *qb;
	struct flowi4 *fl4;
	int err = 0;
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	__wsum csum = 0;


	fl4 = &inet->cork.fl.u.ip4;
	qb = QUIC_SKB_CB(skb);
//clone != 0 -> clone the socket buffer
	if(clone){
		//printk("Number of packets in send queue = %d\n", skb_queue_len(&sk->sk_write_queue));
		//Clone the skb before sending
		skb = skb_clone(skb, GFP_ATOMIC); //with as little memory copy overhead as possible
	
		if(skb == NULL){
			printk("Error cloning skb");
			return 420;
		}
	
		//skb_orphan(skb);
		skb->sk = sk;
		skb->destructor = sock_wfree;
		atomic_add(skb->truesize, &sk->sk_wmem_alloc);
	}


	/*
	 * Create a QUIC header, populated with the control buffer values
	 */


	qh = quic_hdr(skb);
	qh->source = inet->inet_sport;
	qh->dest = fl4->fl4_dport;
	qh->len = htons(len);
	qh->check = 0;
	qh->cid = qb->cid;
	qh->conn_id = qp->conn_id;
	//if(retransmit)
	//	qb->sequence++;
	//qh->sequence = qb->sequence;
	if(clone){
		qh->sequence = qb->sequence = qp->send_next_sequence++; //used to distinguish data packets from other packets like ACK packets
	}else{
		qh->sequence = qb->sequence;
	}

	qh->offset = qb->offset;
	qh->type = qb->type;

	//printk("Sent packet with sequence = %u\n", qh->offset);

	if (sk->sk_no_check == UDP_CSUM_NOXMIT) {   /* QUIC csum disabled */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* QUIC hardware csum */

		udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
		goto send;

	} else{
		csum = quic_csum(skb);
	}

	/* add protocol-dependent pseudo-header */
	//computes checkusum of the TCP/UDP pseudoheader, returns an already complemented result
	qh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
				      sk->sk_protocol, csum);
	if (qh->check == 0)
		qh->check = CSUM_MANGLED_0; //if 0, write as 0xFFFF

	//Timestamp = current time from boot (jiffies)
	qb->timestamp = jiffies;

send:
//what does the L3 send function return? 
	err = ip_send_skb(sock_net(sk), skb);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) { //if error == no buffer space available
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_SNDBUFERRORS, 0);
			err = 0;
		}
		printk("Error sending packet number %u\n", qb->offset);
	} else{ //if "no error" - alright!
		UDP_INC_STATS_USER(sock_net(sk),
				   UDP_MIB_OUTDATAGRAMS, 0);
		if(!retransmit && clone){ //data packet, no retransmission
			qp->packets_out++;
			printk("Sent packet with offset = %u, sequence = %u, Packets out = %u\n", qh->offset, qh->sequence, qp->packets_out);
		}else if(clone){ //data packet, retransmission
			printk("Retransmitted packet with offset = %u, sequence = %u\n", qh->offset, qh->sequence);
		}
//if connections established, data packet sent and we're on client side -> set TLP/RTO timer for fast retransmit
		if(sk->sk_state == TCP_ESTABLISHED && clone && !qp->server){
			//Set Loss timer
			//if(qp->nacked_in_q){
			//	if(!timer_pending(&qp->quic_hshake_loss_timer)){
			//		quic_reset_hshake_loss_timer(sk, 0.25*((qp->srtt)>>3));
			//		printk("Set Loss timer for Fast retransmit\n");
			//	}
			//}

			//Tail Loss Probes
			if(qp->tlp_out < 2){
				if(qp->packets_out == 1){
					quic_reset_rto_tlp_timer(sk, max( 1.5*(qp->srtt>>3)+QUIC_DEL_ACK,  2*(qp->srtt>>3)));
				}else if(qp->packets_out > 1){
					quic_reset_rto_tlp_timer(sk, max( msecs_to_jiffies(10),  2*(qp->srtt>>3)));
				}
			}else if(qp->tlp_out == 2){
				if(!timer_pending(&qp->quic_rto_tlp_timer)){
					printk("In quic finish send......");
					quic_reset_rto_tlp_timer(sk, qp->rto);
				}
			}
		}
	}

	return err;
}
/* This function is called to transmit packets from the send queue, and implements asynchronous packet sending. It first checks whether the queue is empty/packets sent have already filled the congestion window */
int try_send_packets(struct sock *sk){
	struct sk_buff *skb;
	struct quic_sock *qp = quic_sk(sk);
	int err = 0;
//if nothing to send
	qp->sending = 1;
	if(skb_queue_empty(&sk->sk_write_queue)){
		qp->sending = 0;
		return 0;
	}

	//if(qp->packets_out >= QUIC_MAX_SENDBUF){
	//	qp->sending = 0;
	//	return 0;
	//}
//if congestion window full
	if(qp->packets_out >= qp->cwnd){
		qp->sending = 0;
		return 0;
	}
//send packets until the buffer is empty or the congestion window full
	while(qp->packets_out < qp->cwnd){ //as long as cwnd hasn't been filled
		if(IS_ERR_OR_NULL(qp->last_sent)){
			if(skb_queue_empty(&sk->sk_write_queue)){ //if nothing more to send, stop
				qp->sending = 0;
				qp->last_sent = NULL;
				return 0;
			}
			skb = skb_peek(&sk->sk_write_queue); //returns pointer to first item of the list
		}else if(skb_peek_tail(&sk->sk_write_queue) == qp->last_sent){
			qp->sending = 0;
			return 0;
		}else {
			skb = qp->last_sent->next;
		}
		if(!IS_ERR_OR_NULL(skb)){ //if everything's fine, finalize sending
			err = quic_finish_send_skb(skb, 1, 0);	//This will increment qp->packets_out
		}
		if(!err){
			qp->last_sent = skb;
		}
	}
	qp->sending = 0;
	return err;
}
/* This function hands the packets off to the socket by stripping off the QUIC header and checking the checksum for the packet before copying it to the user space */
int quic_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len, int noblock, int flags, int *addr_len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct sockaddr_in *sin = (struct sockaddr_in *)msg->msg_name;
	struct sk_buff *skb;
	unsigned int ulen, copied;
	int peeked, off = 0;
	int err;
	bool checksum_valid = false;
	bool slow;
//if an error has already been detected in the lower layers
	if (flags & MSG_ERRQUEUE){
		return ip_recv_error(sk, msg, len, addr_len);
	}

try_again:
	skb = __skb_recv_datagram(sk, flags | (noblock ? MSG_DONTWAIT : 0),
				  &peeked, &off, &err);
	if (!skb)
		goto out;
//length of buffer - length of header
	ulen = skb->len - sizeof(struct quichdr);
	copied = len;
	if (copied > ulen)
		copied = ulen;
	else if (copied < ulen) //in this case, data is truncated
		msg->msg_flags |= MSG_TRUNC;

	/*
	 * If checksum is needed at all, try to do it while copying the
	 * data.  If the data is truncated, or if we only want a partial
	 * coverage checksum (UDP-Lite), do it before the copy.
	 */
	 
	if (copied < ulen || QUIC_SKB_CB(skb)->partial_cov) {
		checksum_valid = !quic_lib_checksum_complete(skb);
		if (!checksum_valid) //why? 
			goto csum_copy_err; //go to error handling
	}
//TODO: what is he trying to do here? we haven't always calculated checksum_valid...
	if (checksum_valid || skb_csum_unnecessary(skb)){

		err = skb_copy_datagram_iovec(skb, sizeof(struct quichdr),
					      msg->msg_iov, copied);
	}
	else { //in this case, calculate checksum after copying packet!
		err = skb_copy_and_csum_datagram_iovec(skb,
						       sizeof(struct quichdr),
						       msg->msg_iov);
        
		if (err == -EINVAL)
			goto csum_copy_err;
	}
/* likely() and unlikely() are instructions to the compiler for branch prediction -> here, it is expected that there won't be any error. If there is one, though, much more time is lost... */
	if (unlikely(err)) {
		trace_kfree_skb(skb, udp_recvmsg);
		if (!peeked) {
			atomic_inc(&sk->sk_drops);
			UDP_INC_STATS_USER(sock_net(sk),
					   UDP_MIB_INERRORS, 0);
		}
		goto out_free;
	}

	if (!peeked)
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_INDATAGRAMS, 0);
//timestamp and drops
	sock_recv_ts_and_drops(msg, sk, skb);

	/* Copy the address. */
	if (sin) {
		sin->sin_family = AF_INET;
		sin->sin_port = quic_hdr(skb)->source;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);
	}
	if (inet->cmsg_flags){
		ip_cmsg_recv(msg, skb);
	}

	err = copied;
	if (flags & MSG_TRUNC)
		err = ulen;
//socket is freed
out_free:
	skb_free_datagram_locked(sk, skb);
out:
	return err;
//if error during copying or checksum calculation
csum_copy_err:
	printk("Error: quic_recvmsg : csum_copy_err\n");
	slow = lock_sock_fast(sk);
	if (!skb_kill_datagram(sk, skb, flags)) { //free datagram skbuff, increase error stats
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_CSUMERRORS, 0);
		UDP_INC_STATS_USER(sock_net(sk), UDP_MIB_INERRORS, 0);
	}
	unlock_sock_fast(sk, slow);

	/* starting over for a new packet, but check if we need to yield */
	cond_resched();
	msg->msg_flags &= ~MSG_TRUNC;
	goto try_again;
}

//Checksum initialization = calculating the right checksum, if one is needed at all

inline int quic4_csum_init(struct sk_buff *skb, struct quichdr *qh,
				 int proto)
{
	const struct iphdr *iph;

	QUIC_SKB_CB(skb)->partial_cov = 0;
	QUIC_SKB_CB(skb)->cscov = skb->len;


	iph = ip_hdr(skb);
	if (qh->check == 0) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	} else if (skb->ip_summed == CHECKSUM_COMPLETE) {
		if (!csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len,
				      proto, skb->csum))
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
	if (!skb_csum_unnecessary(skb))
		skb->csum = csum_tcpudp_nofold(iph->saddr, iph->daddr,
					       skb->len, proto, 0);
	/* Probably, we should checksum udp header (it should be in cache
	 * in any case) and data in tiny packets (< rx copybreak).
	 */

	return 0;
}
/* implementation = UDP implementation. This routine is called by ICMP module when it gets some sort of error */
int __quic4_lib_mcast_deliver(struct net *net, struct sk_buff *skb,
				    struct quichdr  *qh,
				    __be32 saddr, __be32 daddr,
				    struct udp_table *udptable)
{
	struct sock *sk, *stack[256 / sizeof(struct sock *)];
	struct udp_hslot *hslot = udp_hashslot(udptable, net, ntohs(qh->dest));
	int dif;
	unsigned int i, count = 0;

	spin_lock(&hslot->lock);
	sk = sk_nulls_head(&hslot->head);
	dif = skb->dev->ifindex;
	sk = udp_v4_mcast_next(net, sk, qh->dest, daddr, qh->source, saddr, dif);
	while (sk) {
		stack[count++] = sk;
		sk = udp_v4_mcast_next(net, sk_nulls_next(sk), qh->dest,
				       daddr, qh->source, saddr, dif);
		if (unlikely(count == ARRAY_SIZE(stack))) {
			if (!sk)
				break;
			flush_stack(stack, count, skb, ~0);
			count = 0;
		}
	}
	/*
	 * before releasing chain lock, we must take a reference on sockets
	 */
	for (i = 0; i < count; i++)
		sock_hold(stack[i]);

	spin_unlock(&hslot->lock);

	/*
	 * do the slow work with no lock held
	 */
	if (count) {
		flush_stack(stack, count, skb, count - 1);

		for (i = 0; i < count; i++)
			sock_put(stack[i]);
	} else {
		kfree_skb(skb);
	}
	return 0;
}
//socket buffer is allocated (called in the quic_ip_make_skb function)
int __quic_make_skb(struct sock *sk,
			    struct sk_buff_head *queue,
			    struct inet_cork *cork,
			    int length)
{
	struct sk_buff *skb; //new buffer!
	char *data;
	int hh_len;
	int exthdrlen;
	int err;
	unsigned int fragheaderlen, fraglen, alloclen;
	struct rtable *rt = (struct rtable *)cork->dst;

	skb = skb_peek_tail(queue);

	exthdrlen = rt->dst.header_len;

	hh_len = LL_RESERVED_SPACE(rt->dst.dev);

	fragheaderlen = sizeof(struct iphdr);

//alloc_new_skb:

	fraglen = sizeof(struct quichdr) + fragheaderlen;

	alloclen = fraglen;                 //length of QUIC hdr + ID hdr

	alloclen += exthdrlen;              //extentions header 
	alloclen += rt->dst.trailer_len;    //destination trailer length
	alloclen += length;                 //length of packet (function parameter)

	//alloclen += 200;

	skb = sock_alloc_send_skb(sk,
			alloclen + hh_len + 15,
			0, &err);                   //socket allocation
	if (skb == NULL)                    //if problems...
		goto error;

	/*
	 *	Fill in the control structures
	 */
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum = 0;
	skb_reserve(skb, hh_len);
	skb_shinfo(skb)->tx_flags = cork->tx_flags;

	/*
	 *	Find where to start putting bytes.
	 */
	data = skb_put(skb, fraglen + exthdrlen);           //data after fraglen + exthdrlen
	skb_set_network_header(skb, exthdrlen);             //network header after exthdrlen
	skb->transport_header = (skb->network_header +      //transport header after IP header
				 fragheaderlen);
	/*
	 * Put the packet on the pending queue.
	 */
	__skb_queue_tail(queue, skb);

	return 0;

error:  //increase stats in case of error
	IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTDISCARDS);
	return err;
}
/* allocate both quic and ip socket buffers (called in send_ack, send_connect and reply_connect) */
struct sk_buff *quic_ip_make_skb(struct sock *sk, struct flowi4 *fl4, int length)
{
	struct inet_cork cork;
	struct sk_buff_head queue;
	struct ipcm_cookie ipc;
	struct rtable *rt;
	int err;

	__skb_queue_head_init(&queue);

	// Get the route for IP as the socket is already QUIC connected
	rt = (struct rtable *)sk_dst_check(sk, 0);

	ipc.opt = NULL;
	ipc.tx_flags = 1;
	ipc.ttl = 0;
	ipc.tos = -1;
	ipc.oif = sk->sk_bound_dev_if;
	ipc.addr = fl4->daddr;

	cork.flags = 0;
	cork.addr = 0;
	cork.opt = NULL;
	err = ip_setup_cork(sk, &cork, &ipc, &rt);
	if (err)
		return ERR_PTR(err);

	err = __quic_make_skb(sk, &queue, &cork, length);
	if (err) {                                              //if socket buffer allocation doesn't succeed, flush pending frames and return an error
		__ip_flush_pending_frames(sk, &queue, &cork);
		return ERR_PTR(err);
	}
//data is copied to the socket buffer by the function ip_make_skb 
	return __ip_make_skb(sk, fl4, &queue, &cork);
}
//self-explanatory - find a socket buffer in the send queue as socket and offset are given 
struct sk_buff *find_in_send_q(struct sock *sk, __be32 offset){
	struct sk_buff *skb, *skb_end;
	__be32 prev;
	struct quic_skb_cb *qb;

//if queue is empty, don't bother
	if(skb_queue_empty(&sk->sk_write_queue)){
		//printk("Find in queue failed as the queue is empty\n");
		return NULL;
	}

	skb_end = skb_peek_tail(&sk->sk_write_queue);
	
	qb = QUIC_SKB_CB(skb_end);
	//printk("Largest offset in q = %u\n", qb->offset);

	if(offset > qb->offset){
		//printk("Offset %u bigger than highest offset %u\n", offset, qb->offset);
		return NULL;
	}
	if(qb->offset == offset){
		//printk("Offset %u same as highest offset %u\n", offset, qb->offset);
		return skb_end;
	}
//special cases are treated here -> offset too large, too small, equal to highest/smallest offset
	skb = skb_peek(&sk->sk_write_queue);
	qb = QUIC_SKB_CB(skb);
	//printk("Smallest offset in q = %u\n", qb->offset);

	if(offset < qb->offset){
		//printk("Offset %u smaller than smallest offset %u\n", offset, qb->offset);
		return NULL;
	}
	if(qb->offset == offset){
		//printk("Offset %u same as smallest offset %u\n", offset, qb->offset);
		return skb;
	}

	prev = qb->offset;
	skb = skb->next;
	
	while(skb != skb_end){
		qb = QUIC_SKB_CB(skb);
		//printk("Matching offset %u with the queue item offset %u\n", offset, qb->offset);
//if we already overtook the searched offset, return NULL
		if(offset < qb->offset){
			//printk("Stopping search as queue offset %u greater than offset %u\n", qb->offset, offset);
			return NULL;
		}
		if(qb->offset == offset){
			//printk("Offset %u found\n", offset);
			return skb;
		}


		//Offset didnt match for this skb, go to the next one
		skb = skb->next;
	}

	//printk("Error: Offset %u not found\n", offset);
	return NULL;
}
/*  basically the same as previous function, with two differences
    1. header offset used instead of buffer offset (why?)
    2. only returns whether socket is in the queue
    do we really need this function? */

bool is_in_rcv_q(struct sock *sk, __be32 offset){
	struct sk_buff *skb, *skb_end;
	__be32 prev;
	struct quichdr *qh;

	if(skb_queue_empty(&sk->quic_receive_queue))
		return 0;


	skb_end = skb_peek_tail(&sk->quic_receive_queue);
	
	qh = quic_hdr(skb_end);

	if(offset > qh->offset){
		//printk("Offset %u bigger than highest offset %u\n", offset, qh->offset);
		return 0;
	}
	if(qh->offset == offset){
		//printk("Offset %u same as highest offset %u\n", offset, qh->offset);
		return 1;
	}

	skb = skb_peek(&sk->quic_receive_queue);
	qh = quic_hdr(skb);

	if(offset < qh->offset){
		//printk("Offset %u smaller than smallest offset %u\n", offset, qh->offset);
		return 0;
	}
	if(qh->offset == offset){
		//printk("Offset %u same as smallest offset %u\n", offset, qh->offset);
		return 1;
	}

	prev = qh->offset;
	skb = skb->next;
	
	while(skb != skb_end){
		qh = quic_hdr(skb);

		if(offset < qh->offset)
			return 0;
		if(qh->offset == offset)
			return 1;

		//Offset didnt match for this skb, go to the next one
		skb = skb->next;
	}

	return 0;
}
//deletes ACKed frames and decides what to do (e.g. reset TLP/RTO timers)
int delete_acked(struct sock *sk){
	struct quic_sock *qp = quic_sk(sk);
	struct sk_buff *skb, *skb_temp;
	struct quic_skb_cb *qb;
	int count = 0, position = 0;
	bool end = 0;

	if(skb_queue_empty(&sk->sk_write_queue)){
		printk("delete_acked(): Send queue empty\n");
		return count;
	}

	skb = skb_peek(&sk->sk_write_queue);
	qb = QUIC_SKB_CB(skb);

	//printk("delete_acked()\nfirst packet offset = %u\nHighest acked = %u\n", qb->offset, qp->highest_ack);

	while (qb->offset <= qp->highest_ack){
		position++;
		if(skb == skb_peek_tail(&sk->sk_write_queue))   //if we've reached the end
			end = 1;    
		if(!qb->missing_reports){                       //if no missing reports
			printk("Deleting ACKed frame with offset %u\n", qb->offset);
			if(skb == qp->last_sent){
				if(skb == skb_peek(&sk->sk_write_queue)){
					qp->last_sent = NULL;
				}else{
					qp->last_sent = skb->prev;
				}
			}
			skb_temp = skb->next;
			skb_unlink(skb, &sk->sk_write_queue);
			kfree_skb(skb); //this socket buffer isn't needed anymore - delete
			if(!qp->packets_out) //packets_out should be at least 1
				printk("Error: packets_out is incorrectly  0\n");
			qp->packets_out--;
			count++;
//this part of the code has been already explained in the congestion control part
			//ACK received after RTO
			if(qp->number_rto_packets){
				//If packet other than sent after RTO is ACKed, recover CWND
				if(position > qp->number_rto_packets){
					bictcp_undo_cwnd(sk);
				}
				//case "closed" - packets ACKed after RTO 
				qp->number_rto_packets = 0;
			}

            //TLP/RTO timer handling
			//Restart TLP timer with the usual formula
			if(qp->packets_out == 0){
				if(timer_pending(&qp->quic_rto_tlp_timer))
					quic_clear_rto_tlp_timer(sk);
			}else if(qp->packets_out == 1){
				qp->tlp_out = 0;
				qp->retransmits = 0;
				quic_reset_rto_tlp_timer(sk, max( 1.5*(qp->srtt>>3)+QUIC_DEL_ACK,  2*(qp->srtt>>3)));
			}else if(qp->packets_out > 1){
				qp->tlp_out = 0;
				qp->retransmits = 0;
				quic_reset_rto_tlp_timer(sk, max( msecs_to_jiffies(10),  2*(qp->srtt>>3)));
			}

		}else{
			skb_temp = skb->next;
		}

		if(end)
			return count;       //number of ACKed packets
		skb = skb_temp;
		qb = QUIC_SKB_CB(skb);
	}
	//if no packets are out, or the write queue is empty, or both -> clear the timers
	if(!qp->packets_out || skb_queue_empty(&sk->sk_write_queue)){
		printk("Packets out = %u, clearing the timers\n", qp->packets_out);
		qp->packets_out = 0;
		quic_clear_hshake_loss_timer(sk);
		quic_clear_rto_tlp_timer(sk);
	}
    //change first_unack pointer (first packet which needs to be acknowledged)
	if(skb_queue_empty(&sk->sk_write_queue)){
		qp->first_unack = qp->send_next;
	}else{
	qp->first_unack = QUIC_SKB_CB(skb_peek(&sk->sk_write_queue))->offset;
	}

	return count;

}
//counts the number of ACKed packets (same implementation as in delete_acked())
int count_acked(struct sock *sk){
	struct quic_sock *qp = quic_sk(sk);
	struct sk_buff *skb;
	struct quic_skb_cb *qb;
	int count = 0;
	bool end = 0;
//no packets at all in the write queue
	if(skb_queue_empty(&sk->sk_write_queue)){
		return count;
	}

	skb = skb_peek(&sk->sk_write_queue);
	qb = QUIC_SKB_CB(skb);

	//printk("delete_acked()\nfirst packet offset = %u\nHighest acked = %u\n", qb->offset, qp->highest_ack);

	while (qb->offset <= qp->highest_ack){
		if(skb == skb_peek_tail(&sk->sk_write_queue))
			end = 1;
		if(!qb->missing_reports) //NACK count == 0 -> increment number of ACKed packets
			count++;
		if(end)
			return count;
		skb = skb->next; //jump to next socket buffer
		qb = QUIC_SKB_CB(skb);
	}
	return count;

}

/* retransmit NACKed packets - this function gets called upon loss timer expiration (loss_hshake_timer_handler) */

void retransmit_nacked(struct sock *sk, const unsigned int threshold){ //RESEND_THRESHOLD defined as 3 in header
	struct quic_sock *qp = quic_sk(sk);
	struct sk_buff *skb, *skb_end;
	struct quic_skb_cb *qb;
	int sent = 0;

	printk("Entered retransmit function\n");
	if(skb_queue_empty(&sk->sk_write_queue)){
		printk("Error: send queue empty on loss timer expiration\n");
		return;
	}

	skb = skb_peek(&sk->sk_write_queue);
	skb_end = skb_peek_tail(&sk->sk_write_queue);
	goto first_time;

	do{
		if(IS_ERR_OR_NULL(skb) || IS_ERR_OR_NULL(skb_end))
			return;
		skb = skb->next;
first_time:	
		if(IS_ERR_OR_NULL(skb) || IS_ERR_OR_NULL(skb_end)){
			printk("Error skb in retransmit\n");
			return;
		}
		qb = QUIC_SKB_CB(skb);
		if(IS_ERR_OR_NULL(skb) || IS_ERR_OR_NULL(skb_end)){
			printk("Error skb in retransmit\n");
			return;
		}//similar to TCP's "3-duplicate ACKs" logic -> in this case, fast retransmit
		if(qb->missing_reports > threshold){
			if(IS_ERR_OR_NULL(skb) || IS_ERR_OR_NULL(skb_end)){
				printk("Error skb in retransmit\n");
				return;
			}
			quic_finish_send_skb(skb,1, 1); //send this packet immediately
			sent++;
			qb->missing_reports = 0;
			printk("Fast Retransmitting packet number %u\n", qb->offset);
		}else if(qb->missing_reports == 0){ //packet hasn't been tested at all
			//printk("reached untested packet number %u, breaking\n", qb->offset);
			break;
		}else {
			if(IS_ERR_OR_NULL(skb) || IS_ERR_OR_NULL(skb_end))
				return;
			//printk("Not Retransmitting packet number %u\n", qb->offset);
		}
		if(IS_ERR_OR_NULL(skb) || IS_ERR_OR_NULL(skb_end))
			return;
	}while((skb != skb_end) && (sent <= qp->cwnd)); //as long as write queue/congestion window go
}
/* function has been borrowed from the TCP code to update RTT variables (see Communication Networks lecture) RTO = rtt + 4 * mdev and so on */

static void process_RTT(struct sock *sk, const __u32 mrtt)
{
	struct quic_sock *qp = quic_sk(sk);

	long m = mrtt; /* RTT */

	/*	The following amusing code comes from Jacobson's
	 *	article in SIGCOMM '88.  Note that rtt and mdev
	 *	are scaled versions of rtt and mean deviation.
	 *	This is designed to be as fast as possible
	 *	m stands for "measurement".
	 *
	 *	On a 1990 paper the rto value is changed to:
	 *	RTO = rtt + 4 * mdev
	 *
	 * Funny. This algorithm seems to be very broken.
	 * These formulae increase RTO, when it should be decreased, increase
	 * too slowly, when it should be increased quickly, decrease too quickly
	 * etc. I guess in BSD RTO takes ONE value, so that it is absolutely
	 * does not matter how to _calculate_ it. Seems, it was trap
	 * that VJ failed to avoid. 8)
	 */
	if (m == 0)
		m = 1;
	if (!qp->first_rtt) {
		m -= (qp->srtt >> 3);	/* m is now error in rtt est */
		qp->srtt += m;		/* rtt = 7/8 rtt + 1/8 new */
		if (m < 0) {
			m = -m;		/* m is now abs(error) */
			m -= (qp->mdev >> 2);   /* similar update on mdev */
			/* This is similar to one of Eifel findings.
			 * Eifel blocks mdev updates when rtt decreases.
			 * This solution is a bit different: we use finer gain
			 * for mdev in this case (alpha*beta).
			 * Like Eifel it also prevents growth of rto,
			 * but also it limits too fast rto decreases,
			 * happening in pure Eifel.
			 */
			if (m > 0)
				m >>= 3;
		} else {
			m -= (qp->mdev >> 2);   /* similar update on mdev */
		}
		qp->mdev += m;	    	/* mdev = 3/4 mdev + 1/4 new */
		if (qp->mdev > qp->mdev_max) {
			qp->mdev_max = qp->mdev;
			if (qp->mdev_max > qp->rttvar)
				qp->rttvar = qp->mdev_max;
		}
		if (qp->first_unack > qp->rtt_seq) {
			if (qp->mdev_max < qp->rttvar)
				qp->rttvar -= (qp->rttvar - qp->mdev_max) >> 2;
			qp->rtt_seq = qp->send_next;
			qp->mdev_max = tcp_rto_min(sk);
		}
	} else {
		/* no previous measure. */
		qp->srtt = m << 3;	/* take the measured time to be rtt */
		qp->mdev = m << 1;	/* make sure rto = 3*rtt */
		qp->mdev_max = qp->rttvar = max(qp->mdev, tcp_rto_min(sk));
		qp->rtt_seq = qp->send_next;
		qp->first_rtt = 0;
	}

	//Set RTO
	qp->rto =(qp->srtt >> 3) + qp->rttvar;
	//Clamping at TCP_RTO_MIN not required as the above logic takes care of it
	if(qp->rto > QUIC_RTO_MAX)
		qp->rto = QUIC_RTO_MAX; //if rto too high, cap it to RTO_MAX
}

/*  This function is called if the received packet is an ACK packet. It first checks if this
    is an out-of-order ACK/if send queue is empty (then return). If not, process_RTT is called
    and RTT values are updated */


int process_ack(struct sock *sk, struct sk_buff *skb, struct ack_frame *ack){
	struct sk_buff *skb_temp;
	struct quic_skb_cb *qb;
	struct quic_sock *qp = quic_sk(sk);
	unsigned int count = 0;
	bool found = 0, firsft = 1;
	struct quichdr *qh = quic_hdr(skb);
//ntohl function coverts unsigned integer from network byte order to host byte order
	if(
			((qp->highest_ack == ntohl(ack->offset)) && (qp->highest_ack_sequence <= ntohl(qh->sequence))) //new sequence number
			|| 
			(qp->highest_ack < ntohl(ack->offset)) //bytes which still hadn't been ACKed
	  ){
	   //then, update highest_ack and highest_ack_sequence
			qp->highest_ack = ntohl(ack->offset);
			qp->highest_ack_sequence = ntohl(qh->sequence);
	}else{ //out of order ACK
		printk("Received out of order ACK\nPresent highest offset= %u, sequence = %u\nACK offset = %u, sequence = %u\n", qp->highest_ack, qp->highest_ack_sequence, ntohl(ack->offset), ntohl(qh->sequence));
		return 1;		//Old ACK
	}

	if(skb_queue_empty(&sk->sk_write_queue)){
		printk("ACK received but write queue empty\n");
		return 1;
	}
//received frame is an ACK frame
	if(qp->syn_acked == 0)
		qp->syn_acked = 1;
	ack++;

	skb_temp = find_in_send_q(sk, ntohl(qh->offset));
	qb = QUIC_SKB_CB(skb_temp);
	if(!IS_ERR_OR_NULL(skb_temp)){
		if(qb->sequence != ntohl(qh->sequence)){
			printk("Warning: RTT measurement not valid, sent seq = %u, rcv seq = %u\n", qb->sequence, ntohl(qh->sequence));
			ack++;
			goto process_nack;
		}
	}else{
		printk("Packet with offset %u already acked, skipping RTT measurement....\n", ntohl(qh->offset));
		ack++;
		goto process_nack;
	}
//sampling RTT (DELTA = time difference between when packet was received and packet was sent):
//provides for a better RTT estimate
	if(ntohl(ack->id) == DELTA){ //if this ACK frame carries Delta information
		if(!IS_ERR_OR_NULL(skb_temp)){
			qp->highest_ack_rtt = jiffies - qb->timestamp - (unsigned long) ntohl(ack->offset);
		}else{
			printk("Error: SKB disappeared while taking RTT, skipping....\n");
			ack++;
			goto process_nack;
		}
//if RTT isn't too high, RTO updated according to known algorithm!
		if(qp->highest_ack_rtt < 1000){
			process_RTT(sk, qp->highest_ack_rtt);
			//printk("For Offset %u\nMeasured RTT = %ums, SRTT = %ums\n", qb->offset, qp->highest_ack_rtt, qp->srtt>>3);
		}else{
			printk("Warning: Not processing RTT value for this ACK\n");
			printk("For Offset %u\nNow = %lu\nSent = %u\nDelta value = %u\nMeasured RTT = %u\n", qb->offset, jiffies, qb->timestamp, ntohl(ack->offset), qp->highest_ack_rtt);
		}
		ack++;
	}else{ //if no Delta tag, then the acknowledgment is corrupt
		printk("Error: Corrupt acknowledgement, no Delta tag, tag value = %u\n", ntohl(ack->id));
		return 1;
	}
//check whether there are negative acknowledgments and handle them
process_nack:

	skb_temp = skb_peek(&sk->sk_write_queue);

	//NO NACKs in this ACK
	if(ntohl(ack->id) == END){
		goto start_here;
		//do-while structure is there in order to avoid this!!!
		while(skb_temp != skb_peek_tail(&sk->sk_write_queue)){
			skb_temp = skb_temp->next;
start_here:
			qb = QUIC_SKB_CB(skb_temp);
			if(IS_ERR_OR_NULL(skb_temp)){
				printk("Warning: Dangling skb pointer in write queue....aborting process_ack()\n");
				return -1;
			}
//these frames can be ACKed
			if(qb->offset <= qp->highest_ack){
				qb->missing_reports = 0;
				printk("Acked frame %u\n", qb->offset);
			}else if(qb->offset > qp->highest_ack){
				break;
			}
		}
		qp->nacked_in_q = 0;
		goto processed;
	}

//processing NACK frames, if there are some
	while( ntohl(ack->id) != END){
		if(ntohl(ack->id) != NACK){
			printk("Error: Invalid type for NACK frame\n");
			return -1;
		}

		found = 0;
		goto first_itr;

		while(skb_temp != skb_peek_tail(&sk->sk_write_queue)){
			skb_temp = skb_temp->next;
first_itr:
			if(IS_ERR_OR_NULL(skb_temp)){
				printk("Warning: Dangling skb pointer in write queue....aborting process_ack()\n");
				return -1;
			}
/*  QUIC FACK logic: instead of waiting for 3-duplicate ACKs, each NACKed packet in the send 
    queue has its 'missing reports' incremented as per the equation "missing_reports =
    highest_received_offset - packet_offset. If resend_threshold is exceeded, retransmit. */
			qb = QUIC_SKB_CB(skb_temp);
			if(qb->offset == ntohl(ack->offset)){
				qb->missing_reports+= qp->highest_ack - qb->offset;
				printk("Frame with offset %u NACKed %u times\n", qb->offset, qb->missing_reports);
				if(first){
                			//if(timer_pending(&qp->quic_hshake_loss_timer)){
					if(qp->first_nack < ntohl(ack->offset)){
						if(timer_pending(&qp->quic_hshake_loss_timer))
							quic_clear_hshake_loss_timer(sk);
						qp->first_nack = ntohl(ack->offset);
					}
					first = 0;
				}

				found = 1;
				skb_temp = skb_temp->next;
				count++;        //number of NACKed packets
				break;

			}else if(qb->offset < ntohl(ack->offset)){
				qb->missing_reports = 0;
				printk("Acked frame %u\n", qb->offset);

			}else if(qb->offset > ntohl(ack->offset)){
				printk("Error: NACK not found\nOffset %u greater than NACK %u\n", qb->offset, ntohl(ack->offset));
				break;

			}else{
				printk("Error: Unforseen condition in process_ack()\n");
				return -1;
			}
		}

		ack++;
	}


	printk("NACKed %u packets\n", count);
	qp->nacked_in_q = count;
//if no NACKs, continue here!
processed:
	count = count_acked(sk);
//if no NACKs (which means no out-of-order packets)
	if(!qp->nacked_in_q){
		if(count){
			qp->ca_state = QUIC_CA_Open;
		}
		if(timer_pending(&qp->quic_hshake_loss_timer))
			quic_clear_hshake_loss_timer(sk);
	//	if(timer_pending(&qp->quic_rto_tlp_timer))
	//		quic_clear_rto_tlp_timer(sk);
	}else{
		qp->ca_state = QUIC_CA_Disorder; //order has been "disturbed"
	}

//threshold and congestion window are updated
	bictcp_cong_avoid(sk, qp->highest_ack, count, qp->packets_out);

	if(count)
		bictcp_acked(sk, count, qp->srtt);

//ACKed socket is deleted as it isn't needed anymore
	delete_acked(sk);

	printk("Congestion window = %u, SSThreshold = %u\n", qp->cwnd, qp->ssthresh);
	return 0;
}

/* This function handles actual ACK sending - called by the "possibly_send_ack()" function */

int send_ack(struct sock *sk){
	struct quic_skb_cb *qb;
	struct quic_sock *qp = quic_sk(sk);
	struct sk_buff *skb;
	struct ack_frame *ack_send;
	struct quichdr *qh;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	int err, count = 0;
	__be32 i;
	__be32 *end;

	skb = quic_ip_make_skb(sk, fl4, 1024);

	//skb_queue_tail(&sk->sk_write_queue, skb);

	qb = QUIC_SKB_CB(skb);
	memset(qb, 0, sizeof(struct quic_skb_cb));

	qh = quic_hdr(skb);

	err = PTR_ERR(skb);
	if (!IS_ERR_OR_NULL(skb)){

        //normal case = ACK frame followed by Delta frame for processing time at receiver
		skb_put(skb, sizeof(ack_send->offset));
		ack_send = (struct ack_frame *)&qh->type;
		qb->type = htonl(ACK);
		ack_send->offset = htonl(qp->highest_rcv);
		qb->offset = htonl(qp->highest_rcv);
		qb->sequence = htonl(qp->highest_rcv_sequence);

		//Add the delay info 
		skb_put(skb, sizeof(struct ack_frame));
		ack_send++;
		ack_send->id = htonl(DELTA);
		ack_send->offset = htonl((__be32) (jiffies - qp->highest_rcv_time));

       
		for(i = qp->rcv_next; i < qp->highest_rcv; i++){
			//adding NACK for those missing packets (NACK frame)
			if(!is_in_rcv_q(sk, i)){
				printk("Adding NACK for %u\n", i);
				count++;
				skb_put(skb, sizeof(struct ack_frame));
				ack_send++;
				ack_send->id = htonl(NACK);
				ack_send->offset = htonl(i);
			}
		}
		
		skb_put(skb, sizeof(__be32));
		ack_send++;
		end = (__be32 *)(ack_send);
		*end = htonl(END);
        //END frame at the end of transmission
		printk("Sending ACK for highest offset %u and %d NACKs\n", qp->highest_rcv, count);
		//printk("Delta value = %lu\n", jiffies - qp->highest_rcv_time);

        //go to the function which handles actual packet sending
		err = quic_finish_send_skb(skb, 0, 0);
	}
	return err;
}
/*  sends out ACK for every second packet in normal case, or immediately if recived packet is
    out-of-order. When the first packet is received, timer is set (ACK shall still be sent, even
    if nothing else is sent!) */
void possibly_send_ack(struct sock *sk, int instant){
	struct quic_sock *qp = quic_sk(sk);

	if(instant){ //instant flag = send ACK immediately (received packet is out-of-order)
		if(timer_pending(&qp->quic_del_ack_timer))
			quic_clear_del_ack_timer(sk);
		send_ack(sk);
	}else if(timer_pending(&qp->quic_del_ack_timer)){
		quic_clear_del_ack_timer(sk);
		send_ack(sk);
	}else{
		quic_reset_del_ack_timer(sk, QUIC_DEL_ACK);
	}
}
/*  CONNECTION ESTABLISHMENT - This function creates a hello packet and sets the socket state to
    "TCP_SYN_SENT" (you know what it should mean - nothing else to do with TCP)  */


int quic_send_connect(struct sock *sk, struct sockaddr *uaddr){
	struct quic_sock *qp = quic_sk(sk);
	struct quichdr *qh;
	struct quic_skb_cb *qb;
	//struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct sk_buff *skb;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	//struct quic_skb_cb *qcb;
	int err = 0;

//create new socket buffer
	skb = quic_ip_make_skb(sk, fl4, 500);

	skb_queue_head(&sk->sk_write_queue, skb);
//set parameters
	qb = QUIC_SKB_CB(skb);
	memset(qb, 0, sizeof(struct quic_skb_cb));
	err = PTR_ERR(skb);
	if (!IS_ERR_OR_NULL(skb)){
		qh = quic_hdr(skb);
		if(!qp->send_next)
			qp->first_unack = qp->send_next = 0;

		//qb->offset = qb->sequence = qp->send_next++;
		qb->offset = qp->send_next++;
		qb->cid =1;
		qb->type = htonl(SYN);
		qb->missing_reports = 0;

		qp->conn_id = 420;
//especially: set QUIC socket state
		sk->sk_state = TCP_SYN_SENT;
		printk("Set the QUIC socket state to TCP_SYN_SENT\n");
		err = quic_finish_send_skb(skb, 1, 0);
		if(!err){
			qp->last_sent = skb;
		}else{
			qp->last_sent = NULL;
		}

	}
//set up the handshake timer (here, during connection establishment)
	quic_reset_hshake_loss_timer(sk, 1.5*((qp->srtt)>>3));
	//sk_reset_timer(sk, &qp->quic_hshake_timer, (jiffies + (1.5*qp->rto)));

	return err;                      
                                         
}
/* function pointer: this is the connect call in the quic_prot structure */
int quic_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	int res;
//protection from parallel uncontrolled access
	lock_sock(sk);
	res = __ip4_datagram_connect(sk, uaddr, addr_len);
	release_sock(sk);
	//Plug-in QUIC connection establishment
	printk(" QUIC connection initiated....\n");
	res = quic_send_connect(sk, uaddr);

	return res;
}
/* This function is called at the server side upon receiving a hello packet (see beneath) */
int quic_reply_connect(struct sock *sk, struct sk_buff *skb){
	struct quic_sock *qp = quic_sk(sk);
	struct quichdr *qh = quic_hdr(skb);
	struct sockaddr_in replyaddr;   //a structure to contain a defined internet address
	struct sk_buff *skb_rep;
	struct quic_skb_cb *qb;
	struct inet_sock *inet = inet_sk(sk);
	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
	int err = 0;
/*  SYN cookies are a technique used to resist SYN flood attacks -> avoids dropping connections
    when the SYN queue fills up */
	struct syn_cookie_headless *cookie;
	struct ack_frame *ack;

	printk("Replying to connection request from %pI4:%d with sequence number %u\n", &(ip_hdr(skb)->saddr), ntohs(qh->source), qh->offset);
	
//set parameters for reply address structure
	replyaddr.sin_family= AF_INET;
	replyaddr.sin_port= qh->source;
	replyaddr.sin_addr.s_addr= ip_hdr(skb)->saddr;
	qb = QUIC_SKB_CB(skb);
	//take parameters from header
	if(qp->highest_rcv < qh->offset){
		qp->highest_rcv = qh->offset;
		qp->highest_rcv_sequence = qh->sequence;
		qp->highest_rcv_time = qb->timestamp;
	}else if(qp->highest_rcv == qh->offset){
		if(qp->highest_rcv_sequence <= qh->sequence){
			qp->highest_rcv_sequence = qh->sequence;
			qp->highest_rcv_time = qb->timestamp;
		}
	}

	qp->rcv_next = qp->highest_rcv + 1;
	qp->conn_id = qh->conn_id;
//ipv4 connection is set up -> route calculation and so on
	err = ip4_datagram_connect(sk, (struct sockaddr *) &replyaddr, sizeof(replyaddr));
	if(err){
		printk("Error finding a route to %pI4:%d\n", &(ip_hdr(skb)->saddr), 
					ntohs(qh->source));
		printk("ip4_datagram_connect returned error code %d\n", err);
	}
//create new socket buffer
	skb_rep = quic_ip_make_skb(sk, fl4, 500);

	skb_queue_head(&sk->sk_write_queue, skb_rep);

	qb = QUIC_SKB_CB(skb_rep);
	memset(qb, 0, sizeof(struct quic_skb_cb));

	err = PTR_ERR(skb_rep);
	if (!IS_ERR_OR_NULL(skb_rep)){

		qb->cid = 1;
		qp->first_unack = qp->send_next = 0;

		//qb->offset = qb->sequence = qp->send_next++;
		qb->offset = qp->send_next++;
		//create cookie for security reasons
		cookie = (struct syn_cookie_headless *)skb_put(skb_rep, sizeof(struct syn_cookie_headless));
		qb->type = htonl(SYN_REP);
		qb->missing_reports = 0;
		cookie->cookie = htonl(8182);
		//printk("Addresses\ntype = %p\ncook = %p\n", &qb->type, &cookie->cookie);
        //frame in socket buffer is an ACK frame
		// Change the ACK sending behaviour
		ack = (struct ack_frame *)skb_put(skb_rep, sizeof(struct ack_frame));
		ack->id = htonl(ACK);
		ack->offset = htonl(qp->highest_rcv);
//actual sending
		err = quic_finish_send_skb(skb_rep, 1, 0);
		if(!err){
//if no error, change the socket state: connection has been established
			sk->sk_state = TCP_ESTABLISHED;
			printk("Set the QUIC socket state to TCP_ESTABLISHED after sending Hello reply\n");
		}
		qp->syn_acked = 0;	//Syn Reply not Acked yet
		qp->server = 1;
	}
//out:                                         
	return err;                      

}
/* after verifying the hello reply, this function sets the client socket's state to TCP_ESTABLISHED */
int quic_reply_accept(struct sock *sk, struct sk_buff *skb){
	struct quic_sock *qp = quic_sk(sk);
	struct quic_skb_cb *qb;
	struct quichdr *qh = quic_hdr(skb);
	char *ptr = (char *)&qh->type;
	struct syn_cookie *cookie;
	struct ack_frame *ack;


	printk("Received Hello reply with sequence %u\n", qh->offset);
	if(qp->conn_id == qh->conn_id){ //verify - is it the right connection?
		sk->sk_state = TCP_ESTABLISHED; //set client's socket state to TCP_ESTABLISHED
		printk("Set the QUIC socket state to TCP_ESTABLISHED\n");
//handshake timer not needed anymore!
		quic_clear_hshake_loss_timer(sk);
//send back the same cookie (avoids SYN flooding)
		cookie = (struct syn_cookie *)ptr;
		qp->syn_cookie = ntohl(cookie->cookie);
		ack = (struct ack_frame *)(ptr + sizeof(struct syn_cookie));
		printk("Received acknowledgement for offset %u\n", (ntohl(ack->offset)));

		if(qp->highest_ack < ack->offset)
			qp->highest_ack = ack->offset;
		delete_acked(sk);
//read parameter from socket header
		qb = QUIC_SKB_CB(skb);
		if(qp->highest_rcv < qh->offset){
			qp->highest_rcv = qh->offset;
			qp->highest_rcv_sequence = qh->sequence;
			qp->highest_rcv_time = qb->timestamp;
		}else if(qp->highest_rcv == qh->offset){
			if(qp->highest_rcv_sequence <= qh->sequence){
				qp->highest_rcv_sequence = qh->sequence;
				qp->highest_rcv_time = qb->timestamp;
			}
		}
	
		qp->rcv_next = qp->highest_rcv + 1;

	
		//Change this behavior for the new ACK format

		return 0;
	}
//if wrong connection ID
	printk("improper conn_id(%lld), Expected = %lld\nNot connected\n", qh->conn_id, qp->conn_id);
	return -1;
}

/* Insert the received packet into the corresponding queue */
int insert_rcv_buffer(struct sock *sk, struct sk_buff *skb){
	struct quichdr *qh = quic_hdr(skb);
	struct quichdr *qh_temp;
	struct sk_buff *skb_tmp;
	__be32 seq_prev;

	//If receive queue is empty
	//Add the packet to it
	if(skb_queue_empty(&sk->quic_receive_queue)){
		printk("Receive queue is empty, adding the incoming packet with offset %u to it\n", qh->offset);
		skb_queue_head(&sk->quic_receive_queue, skb);
		return 2; //2 = added to head
	}

	skb_tmp = skb_peek_tail(&sk->quic_receive_queue);
	qh_temp = quic_hdr(skb_tmp);

	//Packet already at receive queue tail
	if(qh->offset == qh_temp->offset){ //which means that it's the same packet
		printk("Received duplicate packet with offset %u\n", qh->offset);
		return 1; //1 = duplicate
	}

	//Received packet offset higher than any other previously received packet offset
	//Add it to the queue tail
	if(after(qh->offset, qh_temp->offset)){ //qh->offset > qh_temp->offset, then queue
		skb_queue_tail(&sk->quic_receive_queue, skb);
		printk("Queueing packet %u to tail, after %u\n", qh->offset, qh_temp->offset);
		return 4; //4 = queued to tail
	}

	skb_tmp = skb_peek(&sk->quic_receive_queue); //skb_tmp = queue HEAD !!!
	qh_temp = quic_hdr(skb_tmp);

	//Packet already at receive queue head
	if(qh->offset == qh_temp->offset){
		printk("Received duplicate packet with offset %u\n", qh->offset);
		return 1; //1 = duplicate
	}
    //if smaller -> add to queue head
	//Received packet offset less than any other previously received packet offset
	//Add it to the queue head
	if(before(qh->offset, qh_temp->offset)){
		skb_queue_head(&sk->quic_receive_queue, skb);
		printk("Queueing packet %u to head, before %u\n", qh->offset, qh_temp->offset);
		return 2; //2 = added to head
	}

    //after special cases are done -> general case: offset is "somewhere" in the queue
	//Find the place in the receive queue
	//to insert the new packet
	
	seq_prev = qh_temp->offset;
	skb_tmp = skb_tmp->next;

	while (1) {
		qh_temp = quic_hdr(skb_tmp);
		//If new packet fits between the 
		//last and present skb
		if(between(qh->offset, seq_prev, qh_temp->offset)){
			//Check that this packet is not already in the queue
			if(qh->offset == seq_prev || qh->offset == qh_temp->offset){
				printk("Received duplicate packet with offset %u\n", qh->offset);
				return 1; //1 = duplicate
			}
			//Add the new packet before the skb_tmp
			skb_insert(skb_tmp, skb, &sk->quic_receive_queue);
			printk("Inserted offset number %u between %u and %u\n", qh->offset, seq_prev, qh_temp->offset);
			break;
		}
		//Check here that this is not the last skb with skb_peek_tail
		if(skb_tmp == skb_peek_tail(&sk->quic_receive_queue))
				break;
		seq_prev = qh_temp->offset;
		skb_tmp = skb_tmp->next; //go on until the tail has been reached
	}
	return 3; //3 = somewhere in the queue
	//TODO: wait -> what if receiving fails? shouldn't there be a "return 0" somewhere? how is this handled by the compiler? (see following function...)
}
/*  This function delivers packets from the receive queue to the socket, unless the next expected
    packet has not been received and we have gaps in the receive queue */


int quic_queue_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int rc;
	struct quichdr *qh;
	struct quic_sock *qp = quic_sk(sk);
	struct ack_frame *ack;
	struct sk_buff *skb_temp;
	char *ptr;
        struct quic_skb_cb *qb;
	int rcv_status = 0;


	/*
	 *	Charge it to the socket, dropping if the queue is full. (see udp_queue_rcv_skb)
	 */
	if (!xfrm4_policy_check(sk, XFRM_POLICY_IN, skb)) //false = invalid IPsec packet (i.e. incorrect checksum)
		goto drop;
	nf_reset(skb); //reset netfilter-related skb-field



	if (rcu_access_pointer(sk->sk_filter) && //returns value of "protected" pointers, without having to dereference them
	    quic_lib_checksum_complete(skb)) //this function is implemented in the header. Nothing else than a redirect to the "usual" checksum calculation
		goto csum_error; //checksum calculation error 

	qh = quic_hdr(skb);
	qb = QUIC_SKB_CB(skb);
	ptr = (char *)&qh->type;
	switch (sk->sk_state) {
	case TCP_ESTABLISHED: //in case a connection has already been established
		if(qh->cid){ //if the header carries a connection ID
			if(ntohl(qh->type) == SYN){
				if(qp->syn_acked){
					//quic_reply_connect(sk, skb);
				}else{
					quic_finish_send_skb(skb_peek(&sk->sk_write_queue), 1, 1);
					printk("Resending SYN reply from queue\n");
					//if it's a SYN frame, resend SYN reply
				}
			}else if(ntohl(qh->type) == SYN_REP){
				if(qp->highest_rcv < qh->offset){
					qp->highest_rcv = qh->offset;
					qp->highest_rcv_sequence = qh->sequence;
					qp->highest_rcv_time = qb->timestamp;
				}else if(qp->highest_rcv == qh->offset){
					if(qp->highest_rcv_sequence <= qh->sequence){
						qp->highest_rcv_sequence = qh->sequence;
						qp->highest_rcv_time = qb->timestamp;
					}
				}
            //if it's a SYN reply, change parameters
			}else
			//no correct SYN request/reply - drop frame
				printk("QUIC: Improper SYN request/reply from %pI4:%u\n", &ip_hdr(skb)->saddr, ntohs(qh->source));
			goto drop;
			//a data packet has been received
		}else if(ntohl(qh->type) == DATA){
			printk("**************\nReceived Data packet\n");
            //in-order reception: new highest packet number
			if(qp->highest_rcv < qh->offset){
				printk("New highest received packet number %u, sequence = %u\n", qh->offset, qh->sequence);
				qp->highest_rcv = qh->offset;
				qp->highest_rcv_sequence = qh->sequence;
				qp->highest_rcv_time = qb->timestamp;
			//duplicate of highest received packet number, possibly with newer sequence number
			}else if(qp->highest_rcv == qh->offset){
				if(qp->highest_rcv_sequence <= qh->sequence){
				printk("Duplicate highest received packet number %u, sequence = %u, old seuence = %u\n", qh->offset, qh->sequence, qp->highest_rcv_sequence);
					qp->highest_rcv_sequence = qh->sequence;
					qp->highest_rcv_time = qb->timestamp;
				}
			}
			if(qp->syn_acked == 0){
				qp->syn_acked = 1; //the SYN reply has been surely ACKed, if we're already at this stage
				if(qp->server){ //if this socket is the server
					quic_clear_rto_tlp_timer(sk);
					quic_clear_hshake_loss_timer(sk);
//take head of the write queue away and free it
					skb_temp = skb_peek(&sk->sk_write_queue);
					skb_unlink(skb_temp, &sk->sk_write_queue);
					kfree_skb(skb_temp);
				}
			}

			break;
//if an ACK frame has been received
		}else if(ntohl(qh->type) == ACK){
			ack = (struct ack_frame *)ptr;
			if(qp->first_ack){
			//whole congestion control procedure is started
			//but beware -> no updates for retransmissions (or?)
				bictcp_init(sk);
				qp->first_ack = 0;
			}
			printk("**************\nReceived ACK packet with highest offset %u\n", ntohl(ack->offset)); //process ACK
			process_ack(sk, skb, ack);
			printk("Packets out after ACK processing = %u\n", qp->packets_out);
			if(qp->nacked_in_q){
				if(!timer_pending(&qp->quic_hshake_loss_timer)){
					quic_reset_hshake_loss_timer(sk, 0.25*((qp->srtt)>>3));
					//not ACKed packet -> set LOSS timer
					printk("Set Loss timer for Fast retransmit at %lu\n", jiffies);
				}
				//retransmit_nacked(sk, RESEND_THRESHOLD);
				if(!IS_ERR_OR_NULL(qp->last_sent)){
					if(qp->highest_ack == (QUIC_SKB_CB(qp->last_sent))->offset){
						//Set Early retransmit timer
						quic_reset_early_retrans_timer(sk, 0.255*(qp->srtt >>3));
					}
				}else{ //not ACKed, corrupt packets in queue
					printk("Error: Nacked packets present in Q but corrupt qp->last_sent\n");
				}
			} //if it isn't already sending something else
			if(!qp->sending){
				try_send_packets(sk);
			}else{
				printk("Postponing sending packets as previous send still in progress\n");
			}
			goto drop; //drop packet
		}else
			goto drop;
	case TCP_CLOSE: //if the connection is closed
		if(qh->cid){
			if(ntohl(qh->type) == SYN){ //send a SYN reply 
				quic_reply_connect(sk, skb);
			}else
				printk("QUIC: Improper SYN request from %pI4:%u\n", &ip_hdr(skb)->saddr, ntohs(qh->source));
		}
		goto drop;
	case TCP_SYN_SENT: //if SYN_REP sent
		if(qh->cid){
			if(ntohl(qh->type) == SYN_REP){
				printk("SYN Reply received\n");
				quic_reply_accept(sk, skb); //send (another) reply accept packet
			}else
				printk("QUIC: Improper SYN reply from %pI4:%u\n", &ip_hdr(skb)->saddr, ntohs(qh->source));
		}
		goto drop;
	}


	//If packet is out of bounds of the window
	//Drop it
	//if(!between(qh->offset, qp->rcv_next, qp->rcv_next+qp->cwnd-1)){
	if(qh->offset < qp->rcv_next){
		printk("Received duplicate packet with offset = %u\n", qh->offset);
		possibly_send_ack(sk, 1);
		goto drop;
	}
	//insert the packet into the corresponding queue
	rcv_status = insert_rcv_buffer(sk, skb);

	if(rcv_status == 1){
		//If duplicate packet
		//Send ACK and Drop the packet
		possibly_send_ack(sk, 0);
		goto drop;
	}else if(rcv_status == 0){
		//Insert in receive buffer failed
		goto drop;
	}else if(rcv_status == 2){
		//Insert at receive buffer head
		possibly_send_ack(sk, 0);
	}else{
		//Out of order packet received
		//Instantly send ACK
		possibly_send_ack(sk, 1); //1 -> immediately
	}

	rc = 0;

	while(!skb_queue_empty(&sk->quic_receive_queue)){
		skb = skb_peek(&sk->quic_receive_queue);
		if(skb == NULL)
			break;
		qh = quic_hdr(skb);

		//Check if this is the packet to be received
		if(qh->offset != qp->rcv_next){
			printk("First packet in the read window not yet received\nFirst packet seq %u\nExpected packet seq %u\n", qh->offset, qp->rcv_next);
			break;
		}
//take current buffer away from receive queue
		skb_unlink(skb, &sk->quic_receive_queue);

		if(skb == NULL)
			continue;

		if (sk_rcvqueues_full(sk, skb, sk->sk_rcvbuf)){
			skb_queue_head(&sk->quic_receive_queue, skb); //add skb to the head
			break;
		}

		ipv4_pktinfo_prepare(sk, skb);
		bh_lock_sock(sk);
		if (!sock_owned_by_user(sk)){
			rc = __udp_queue_rcv_skb(sk, skb); //receive function as implemented in UDP
			qp->rcv_next++;
		}
		else if (sk_add_backlog(sk, skb, sk->sk_rcvbuf)) {
			bh_unlock_sock(sk);
			skb_queue_head(&sk->quic_receive_queue, skb);
			break;
		}
		bh_unlock_sock(sk);
		printk("Packets left in read buffer = %u\n", skb_queue_len(&sk->quic_receive_queue));

	}

	return rc;

csum_error: //in case of error
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_CSUMERRORS, 0);
drop: //dropping packet (e.g. if queue is full, or other error)
	UDP_INC_STATS_BH(sock_net(sk), UDP_MIB_INERRORS, 0); //number of erroneous packets increased
	atomic_inc(&sk->sk_drops); //number of drops (atomically) increased
	kfree_skb(skb); //buffer freed
	return -1; //return -> error
}

int __quic4_lib_rcv(struct sk_buff *skb, struct udp_table *udptable,
		   int proto)
{
	struct sock *sk;
	struct quichdr *qh;
	unsigned short ulen;
	struct rtable *rt = skb_rtable(skb);
	__be32 saddr, daddr;
	struct net *net = dev_net(skb->dev);
	struct quic_skb_cb *qb;


	//Timestamp the packet
	qb = QUIC_SKB_CB(skb);
	qb->timestamp = jiffies;


	/*
	 *  Validate the packet.
	 */
	 //if there is a block of free space at least big enough for the header
	if (!pskb_may_pull(skb, sizeof(struct quichdr))){
		printk("Incoming packet: No space for Header");
		goto drop;		/* No space for header. */
	}

	qh   = quic_hdr(skb);
	ulen = ntohs(qh->len);
	saddr = ip_hdr(skb)->saddr;
	daddr = ip_hdr(skb)->daddr;

	if (ulen > skb->len)
		goto short_packet;

	/* UDP validates ulen. */
	if (ulen < sizeof(*qh) || pskb_trim_rcsum(skb, ulen))
		goto short_packet;
	qh = quic_hdr(skb);
//check the checksum
	if (quic4_csum_init(skb, qh, proto)){
		goto csum_error;
	}
//sk = skb->sk
	sk = skb_steal_sock(skb);
	if (sk) {
	//destination cache definition
		struct dst_entry *dst = skb_dst(skb);
		int ret;
 //in the unlikely event that the packet has been delivered to the wrong destination
		if (unlikely(sk->sk_rx_dst != dst))
			udp_sk_rx_dst_set(sk, dst);

		ret = quic_queue_rcv_skb(sk, skb);
		sock_put(sk);
		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret; //return value should be negative
		return 0;
	} else {
		if (rt->rt_flags & (RTCF_BROADCAST|RTCF_MULTICAST))
			return __quic4_lib_mcast_deliver(net, skb, qh,
					saddr, daddr, udptable);
//in case of error, call error routine and lookup in the UDP table to find the socket
		sk = __udp4_lib_lookup_skb(skb, qh->source, qh->dest, udptable);
	}

	if (sk != NULL) {
		int ret;

		ret = quic_queue_rcv_skb(sk, skb);
		sock_put(sk);

		/* a return value > 0 means to resubmit the input, but
		 * it wants the return to be -protocol, or 0
		 */
		if (ret > 0)
			return -ret;
		return 0;
	}
//as in previous function - policy check basically means "checksum"
	if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto drop;
	nf_reset(skb); //reset netfilter parameters

	/* No socket. Drop packet silently, if checksum is wrong */
	if (quic_lib_checksum_complete(skb)){
		goto csum_error; 
	}

	UDP_INC_STATS_BH(net, UDP_MIB_NOPORTS, proto == IPPROTO_UDPLITE);
	//if there are problems -> send ICMP messages "destination unreachable" and "port unreachable"
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);

	/*
	 * Hmm.  We got a QUIC packet to a port to which we
	 * don't wanna listen.  Ignore it.
	 */
	kfree_skb(skb); //don't do anything, drop the packet
	return 0;
//drop packet because payload length doesn't match the actual length received
short_packet:
	LIMIT_NETDEBUG(KERN_DEBUG "QUIC: short packet: From %pI4:%u %d/%d to %pI4:%u\n",
		       &saddr, ntohs(qh->source),
		       ulen, skb->len,
		       &daddr, ntohs(qh->dest));
	goto drop;

csum_error:
	/*
	 * RFC1122: OK.  Discards the bad packet silently (as far as
	 * the network is concerned, anyway) as per 4.1.3.4 (MUST).
	 */
	LIMIT_NETDEBUG(KERN_DEBUG "QUIC: bad checksum. From %pI4:%u to %pI4:%u ulen %d\n",
		       &saddr, ntohs(qh->source), &daddr, ntohs(qh->dest),
		       ulen);
	UDP_INC_STATS_BH(net, UDP_MIB_CSUMERRORS, proto == IPPROTO_UDPLITE);
drop: //increase number of error in UDPLite, then drop the packet
	UDP_INC_STATS_BH(net, UDP_MIB_INERRORS, proto == IPPROTO_UDPLITE);
	kfree_skb(skb);
	return 0;
}
/*
 * Throw away all pending data and cancel the corking. Socket is locked.
 */
void quic_flush_pending_frames(struct sock *sk)
{
	struct quic_sock *qp = quic_sk(sk);

	if (qp->pending) {
		qp->len = 0;
		qp->pending = 0;
		ip_flush_pending_frames(sk); //call lower-layer function - throw everything away
	}
}
//EXPORT_SYMBOL(quic_flush_pending_frames);
/* Wait for a socket to get into the connected state. Must be called with the socket locked. */
int quic_wait_connect(struct sock *sk, long *timeo_p)
{
        struct task_struct *tsk = current;
        DEFINE_WAIT(wait);
        int done;

        do {
                int err = sock_error(sk);
                if (err)
                        return err;
                if (!*timeo_p)          //for how long to wait
                        return -EAGAIN; //Resource (temporarily) unavailable
                if (signal_pending(tsk))
                        return sock_intr_errno(*timeo_p);

                prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
                sk->sk_write_pending++;
                done = sk_wait_event(sk, timeo_p,
                                     sk->sk_state == TCP_ESTABLISHED);
                //busy waiting until the connection state has changed                     
                finish_wait(sk_sleep(sk), &wait);
                sk->sk_write_pending--;
        } while (!done);
        return 0;
}
/* As defined in the quic_prot structure, this function is called whenever data is to be sent by the socket send call! Implemented partially from the udp_sendmsg function code */
int quic_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t len)
{
	struct inet_sock *inet = inet_sk(sk);
	struct quic_sock *qp = quic_sk(sk);
	struct flowi4 fl4_stack;
	struct flowi4 *fl4;
	int ulen = len;
	struct ipcm_cookie ipc;
	struct rtable *rt = NULL;
	int free = 0, flags;
	int connected = 0;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	u8  tos;
	int err;
	int corkreq = qp->corkflag || msg->msg_flags&MSG_MORE;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;
	struct quic_skb_cb *qb;
	long timeo;

	//printk("Total packets in send queue before making skb = %u\n", skb_queue_len(&sk->sk_write_queue));

	flags = msg->msg_flags;

	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

//1. check whether the socket is in connected state or not

	/* Wait for a connection to finish. One exception is TCP Fast Open
	 * (passive side) where data is allowed to be sent before a connection
	 * is fully established.
	 */
	if(sk->sk_state == TCP_CLOSE){ //no connection has been established so far!
		printk("Error: No connection established before sending data\n");
		release_sock(sk); //function returns with an error!
		return -1;
	}else if(sk->sk_state == TCP_SYN_SENT){ //connection has been initiated but the socket is still in the process of completing the connection handshake -> wait
		printk("Waiting for connection request to finish\n");
		if ((err = quic_wait_connect(sk, &timeo)) != 0){
			printk("Error waiting\n");
			release_sock(sk);
			return -2; //different error code
		}
	}


//length field is checked
	if (len > 0xFFFF)
		return -EMSGSIZE;

	/*
	 *	Check the flags passed on to the function
	 */
//MSG_OOB (out of band data) is the only invalid flag for UDP/QUIC
	if (msg->msg_flags & MSG_OOB) /* Mirror BSD error message compatibility */
		return -EOPNOTSUPP; //error: operation not supported at transport endpoint

	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;

	getfrag = ip_generic_getfrag;

	fl4 = &inet->cork.fl.u.ip4;
//add length of QUIC header
	ulen += sizeof(struct quichdr);

//destination address and destination port are pulled from the socked structure
	daddr = inet->inet_daddr;
	dport = inet->inet_dport;
	/* Open fast path for connected socket.
	   Route will not be used, if at least one option is set.
	 */
	connected = 1; //connection has been established
	
	ipc.addr = inet->inet_saddr;

	ipc.oif = sk->sk_bound_dev_if;
//transmission timestamp
	sock_tx_timestamp(sk, &ipc.tx_flags);
//RCU-callback structures (?)

	if (!ipc.opt) {
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) {
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

	saddr = ipc.addr;
	ipc.addr = faddr = daddr;


	tos = get_rttos(&ipc, inet);

//special case: multicast addresses
	if (ipv4_is_multicast(daddr)) {
		if (!ipc.oif)
			ipc.oif = inet->mc_index;
		if (!saddr)
			saddr = inet->mc_addr;
		connected = 0;
	} else if (!ipc.oif)
		ipc.oif = inet->uc_index;
//if there is a connection, check for destination (pointer to a routing entry is stored)
	if (connected)
		rt = (struct rtable *)sk_dst_check(sk, 0);
//route calculation, if it hasn't already happened
	if (rt == NULL) {
		struct net *net = sock_net(sk);

		fl4 = &fl4_stack;
		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   inet_sk_flowi_flags(sk)|FLOWI_FLAG_CAN_SLEEP,
				   faddr, saddr, dport, inet->inet_sport);

		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
//if route is not present (e.g. first packet in a socket) then ip_route_output_flow() determines a route		
		rt = ip_route_output_flow(net, fl4, sk);
//if no outbound route found
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
				//error - no outbound routes - abort
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	if (msg->msg_flags&MSG_CONFIRM) //tell link layer that forward progress happened
		goto do_confirm;
back_from_confirm:

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;
//corkreq signals whether buffering should be used (local flag). If this is set to false, an immediate transmission of the data will be forced
	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		skb = ip_make_skb(sk, fl4, getfrag, msg->msg_iov, ulen,
				  sizeof(struct quichdr), &ipc, &rt,
				  msg->msg_flags);  //socket buffer is allocated for the data and data is copied to it

		err = PTR_ERR(skb);         //=1 if there are errors
		if (!IS_ERR_OR_NULL(skb)){  //if everything's fine
			qb = QUIC_SKB_CB(skb);
			memset(qb, 0, sizeof(struct quic_skb_cb)); //fill this block of memory with zeros (i.e. initialize the struct)

			//qb->offset = qb->sequence = qp->send_next++;
			qb->offset = qp->send_next++;//set the offset value
			qb->type = htonl(DATA);	    //It's a data frame (network notation)
			qb->missing_reports = 0;    //being sent for the first time


			//printk("Queuing packet to send buffer\n");
			skb_queue_tail(&sk->sk_write_queue, skb);   //added at the end of the queue
			//printk("Total packets in send queue = %u\n", skb_queue_len(&sk->sk_write_queue));
			try_send_packets(sk);   //try to send the packets from the send queue (asynchronous packet sending)
		}
		goto out;
	}

//To Support quic_sendpage
//	lock_sock(sk);
//	if (unlikely(qp->pending)) {
//		/* The socket is already corked while preparing it. */
//		/* ... which is an evident application bug. --ANK */
//		release_sock(sk);
//
//		LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("cork app bug 2\n"));
//		err = -EINVAL;
//		goto out;
//	}
//	/*
//	 *	Now cork the socket to pend data.
//	 */
//	fl4 = &inet->cork.fl.u.ip4;
//	fl4->daddr = daddr;
//	fl4->saddr = saddr;
//	fl4->fl4_dport = dport;
//	fl4->fl4_sport = inet->inet_sport;
//	qp->pending = AF_INET;
//
//	qp->len += ulen;
//	err = ip_append_data(sk, fl4, getfrag, msg->msg_iov, ulen,
//			     sizeof(struct quichdr), &ipc, &rt,
//			     corkreq ? msg->msg_flags|MSG_MORE : msg->msg_flags);
//	if (err)
//		quic_flush_pending_frames(sk);
//	else if (!corkreq)
//		err = quic_push_pending_frames(sk);
//	else if (unlikely(skb_queue_empty(&sk->sk_write_queue)))
//		qp->pending = 0;
//	release_sock(sk);



//in case of error - increase error stats, release socket and return with error code
out:
	ip_rt_put(rt);
	if (free)
		kfree(ipc.opt);
	if (!err)
		return len; //out will be reached even if there is no error - in this case, the length field will be returned.
	/*
	 * ENOBUFS = no kernel mem, SOCK_NOSPACE = no sndbuf space.  Reporting
	 * ENOBUFS might not be good (it's not tunable per se), but otherwise
	 * we don't have a good statistic (IpOutDiscards but it can be too many
	 * things).  We could add another new stat but at least for now that
	 * seems like overkill.
	 */
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags)) {
		UDP_INC_STATS_USER(sock_net(sk),
				UDP_MIB_SNDBUFERRORS, 0);
	}

	release_sock(sk);

	return err;

do_confirm:
	dst_confirm(&rt->dst); //confirms the validity of the routing table cache entry and therefore the L3 to L2 mapping
	if (!(msg->msg_flags&MSG_PROBE) || len)
		goto back_from_confirm;
	err = 0;
	goto out;
}
//EXPORT_SYMBOL(quic_sendmsg);

/*
 * Push out all pending data as one QUIC datagram. Socket is locked.
 */
//int quic_push_pending_frames(struct sock *sk)
//{
//	struct quic_sock  *qp = quic_sk(sk);
//	struct quic_skb_cb *qb;
//	struct sk_buff *skb;
//	struct inet_sock *inet = inet_sk(sk);
//	struct flowi4 *fl4 = &inet->cork.fl.u.ip4;
//	int err = 0;
//
//	skb = ip_finish_skb(sk, fl4);
//	if (!skb)
//		goto out;
//
//	skb_queue_tail(&sk->sk_write_queue, skb);
//
//	qb = QUIC_SKB_CB(skb);
//	memset(qb, 0, sizeof(struct quic_skb_cb));
//
//	//qb->offset = qb->sequence = qp->send_next++;
//	qb->offset = qp->send_next++;
//	qb->type = htonl(DATA);	//It's a data frame
//	qb->missing_reports = 0;
//
//	err = try_send_packets(sk);
//	//err = quic_finish_send_skb(skb, 1, 0);
//
//out:
//	qp->len = 0;
//	qp->pending = 0;
//	return err;
//}
//EXPORT_SYMBOL(quic_push_pending_frames);
//
//
//
//int quic_sendpage(struct sock *sk, struct page *page, int offset,
//		 size_t size, int flags)
//{
//	struct inet_sock *inet = inet_sk(sk);
//	struct quic_sock *qp = quic_sk(sk);
//	int ret;
//
//	printk("quic_sendpage called\n");
//	if (flags & MSG_SENDPAGE_NOTLAST)
//		flags |= MSG_MORE;
//
//	if (!qp->pending) {
//		struct msghdr msg = {	.msg_flags = flags|MSG_MORE };
//
//		/* Call quic_sendmsg to specify destination address which
//		 * sendpage interface can't pass.
//		 * This will succeed only when the socket is connected.
//		 */
//		ret = quic_sendmsg(NULL, sk, &msg, 0);
//		if (ret < 0){
//			return ret;
//		}
//	}
//
//	lock_sock(sk);
//
//	if (unlikely(!qp->pending)) {
//		release_sock(sk);
//
//		LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("quic cork app bug 3\n"));
//		return -EINVAL;
//	}
//
//	ret = ip_append_page(sk, &inet->cork.fl.u.ip4,
//			     page, offset, size, flags);
//	if (ret == -EOPNOTSUPP) {
//		release_sock(sk);
//		return sock_no_sendpage(sk->sk_socket, page, offset,
//					size, flags);
//	}
//	if (ret < 0) {
//		quic_flush_pending_frames(sk);
//		goto out;
//	}
//
//	qp->len += size;
//	if (!(qp->corkflag || (flags&MSG_MORE)))
//		ret = quic_push_pending_frames(sk);
//	if (!ret)
//		ret = size;
//out:
//	release_sock(sk);
//	return ret;
//}





