/*
 * Control Plane program for Tofino-based Timesync program.
 * Compile using following command : make ARCH=Target[tofino|tofinobm]
 * To Execute, Run: ./dejavu_cp
 *
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <stddef.h>
 #include <stdint.h>
 #include <sched.h>
 #include <string.h>
 #include <time.h>
 #include <assert.h>
 #include <unistd.h>
 #include <pthread.h>
 #include <unistd.h>
 #include <bfsys/bf_sal/bf_sys_intf.h>
 #include <dvm/bf_drv_intf.h>
 #include <lld/lld_reg_if.h>
 #include <lld/lld_err.h>
 #include <lld/bf_ts_if.h>
 #include <knet_mgr/bf_knet_if.h>
 #include <knet_mgr/bf_knet_ioctl.h>
 #include <bf_switchd/bf_switchd.h>
 #include <pkt_mgr/pkt_mgr_intf.h>
 #include <tofino/pdfixed/pd_common.h>
 #include <tofino/pdfixed/pd_mirror.h>
 #include <tofino/pdfixed/pd_conn_mgr.h>
 #include <pcap.h>
 #include <arpa/inet.h>


#include <tofinopd/dejavu/pd/pd.h>

#include <tofino/pdfixed/pd_common.h>
#include <tofino/pdfixed/pd_conn_mgr.h>

#define THRIFT_PORT_NUM 7777
#define DPTP_FOLLOWUP 0x6
#define DPTP_GEN_REQ 0x11
#define P4_PKTGEN_APP_LCOUNTER 0x5
#define PACKETGEN_GAP 1000000 // in ns
#define MAX_SIZE 100000

#define DPTP_SWITCH5 0x5
#define DPTP_MASTER 0xA

char switchName[25];

p4_pd_sess_hdl_t sess_hdl;

typedef struct __attribute__((__packed__)) p4sync_t {
  uint8_t dstAddr[6];
  uint8_t srcAddr[6];
  uint16_t type;
	uint16_t magic;
	uint8_t command;
	uint32_t reference_ts_hi;
	uint32_t reference_ts_lo;
	uint32_t eraTs;
	uint32_t delta;
	uint8_t igMacTs[6];
	uint8_t igTs[6];
	uint8_t egTs[6];
} dptp;

typedef struct __attribute__((__packed__)) coal_t {
  uint8_t dstAddr[6];
  uint16_t type;
  uint32_t coal_test;
} coal;

typedef struct __attribute__((__packed__)) tcp_t {
  uint8_t ethdstAddr[6];
  uint16_t ethtype;
  uint8_t version_ihl;
  uint8_t diffserv;
  uint16_t totalLen;
  uint16_t identification;
  uint16_t flags_fragoffset;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t ipchecksum;
  uint32_t ipsrcAddr;
  uint32_t ipdstAddr;
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seqNo;
  uint32_t ackNo;
  uint8_t dataOffset_res;
  uint8_t flags;
  uint16_t window;
  uint16_t tcpchecksum;
  uint16_t urgentPtr;
  uint32_t interval;
  uint32_t cwnd;
  uint32_t rtt;
  uint32_t tau;
  int feedback;
  uint8_t payload[16];
} tcp;

typedef struct __attribute__((__packed__)) trig_t {
  uint8_t dstAddr[6];
  uint8_t srcAddr[6];
  uint16_t type;
  uint32_t trigger_id;
  uint32_t pad1;
  uint32_t pad2;
} trig;

typedef struct __attribute__((__packed__)) precord_t {
  uint8_t dstAddr[6];
  uint8_t srcAddr[6];
  uint16_t type;
  uint8_t duration[6];
  uint8_t pad1;
  uint8_t tot_entries;
  uint8_t entries;
} precord;

// DPTP Followup
dptp dptp_followup_pkt;
uint8_t *upkt;
size_t sz = sizeof(dptp);
bf_pkt *bfpkt = NULL;
// DPTP Request
dptp dptp_request_pkt;
size_t dptp_sz = sizeof(dptp);

uint8_t *dreqpkt1;
bf_pkt *bfdptppkt1 = NULL;

uint8_t *dreqpkt2;
bf_pkt *bfdptppkt2 = NULL;

uint8_t *dreqpkt3;
bf_pkt *bfdptppkt3 = NULL;

uint8_t *dreqpkt4;
bf_pkt *bfdptppkt4 = NULL;

uint8_t *dreqpkt5;
bf_pkt *bfdptppkt5 = NULL;

uint8_t *dreqpkt6;
bf_pkt *bfdptppkt6 = NULL;

uint8_t *dreqpkt7;
bf_pkt *bfdptppkt7 = NULL;

uint8_t *dreqpkt8;
bf_pkt *bfdptppkt8 = NULL;

uint8_t *dreqpkt9;
bf_pkt *bfdptppkt9 = NULL;

uint8_t *dreqpkt10;
bf_pkt *bfdptppkt10 = NULL;



uint8_t *ppkt;
uint8_t *tpkt;
uint8_t *prpkt;
coal coal_pkt;
tcp tcp_pkt;
trig trigger_pkt;
trig precord_pkt;

//uint8_t *pkt;
size_t trig_sz = sizeof(trig);
size_t coal_sz = sizeof(coal);
size_t tcp_sz  = sizeof(tcp);
size_t precord_sz = sizeof(precord);
bf_pkt *bftrigpkt = NULL;
bf_pkt *bfprecordpkt = NULL;
bf_pkt_tx_ring_t tx_ring = BF_PKT_TX_RING_1;

int switchid = 0;

/* Increment the era_hi register, upon timestamp wrap */
void increment_era() {
	int dev_id = 0;
	int count =2;
	uint32_t era_hi[count];
	p4_pd_dev_target_t p4_dev_tgt = {dev_id, (uint16_t)PD_DEV_PIPE_ALL};
	p4_pd_status_t status = 0;

	printf("****** Incrementing Era ******\n");
	status = p4_pd_begin_txn(sess_hdl, true);
	if (status != 0) {
		printf("Failed to begin transaction err=%d\n", status);
		return;
	}
	/* Init done hopefully, now read the register val */
	// status = p4_pd_dejavu_register_read_era_ts_hi(sess_hdl, p4_dev_tgt, 0, REGISTER_READ_HW_SYNC,  era_hi, &count);
	// if (status !=0) {
	// 	printf("Failed reading the era_ts_hi register.\n");
	// 	return;
	// }
	printf("era_hi[0] = %X (%d)", era_hi[0], count);
	era_hi[0] = era_hi[0] + 65536;
	printf("Incrementing era_hi to %X\n", era_hi[0]);

	status = p4_pd_complete_operations(sess_hdl);
	(void)p4_pd_commit_txn(sess_hdl, true);
	printf("***** Done ****\n");
}

/* Monitor global_ts, and check for wrap over */
void *monitor_global_ts(void *args) {
	bf_status_t status;
	uint64_t global_ts_ns_old;
	uint64_t global_ts_ns_new;
	uint64_t baresync_ts_ns;

	while (1) {
	 	status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_old, &baresync_ts_ns);
	 	sleep(2);
	 	status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_new, &baresync_ts_ns);

	 	if (global_ts_ns_new < global_ts_ns_old) {
	 		// Wrap Detected.
	 		increment_era();
	 	}
	 	sleep(2);
 	}
}

#define TOTAL_SAMPLES 10000

int drift = 30300;
//int sleep_dur = 5;
uint32_t max_ns = 1000000000;


void *capture_timesyncs2s(void *args) {
	bf_dev_port_t reqport = 160;
	bf_dev_port_t respport = 176;
	uint64_t capture_req_ts;
	uint64_t capture_resp_ts;
	bool ts_valid1, ts_valid2;
	int ts_id1, ts_id2;
	bf_status_t status1;
	bf_status_t status2;

	while(1) {

		status1 = bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, reqport, &capture_req_ts, &ts_valid1, &ts_id1);
		status2 = bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, respport, &capture_resp_ts, &ts_valid2, &ts_id2);

		if (status1 == BF_SUCCESS) {
			printf("Capture Req Ts = %lu %d %d\n", capture_req_ts, ts_valid1, ts_id1);
		}
		if (status2 == BF_SUCCESS) {
			printf("Capture Resp Ts = %lu %d %d\n", capture_resp_ts, ts_valid2, ts_id2);
		}
		sleep(1);
	}
}

void *monitor_timesynctopo_64(void *args) {
	FILE *fc_sxs4 = fopen("logs/dptp_sxs4.log", "w");
  FILE *fc_s4s5 = fopen("logs/dptp_s4s5.log", "w");
  FILE *fc_sxm = fopen("logs/dptp_sxm.log", "w");

  struct timespec tsp;
  tsp.tv_sec = 0;
  tsp.tv_nsec = 600000;

	int count = 2;
	uint32_t cp_flag[count];
	uint32_t s2s_reference_hi[count], s2s_reference_lo[count];
	uint32_t reference_hi_master[count], reference_lo_master[count];
  uint32_t reference_hi_s4[count], reference_lo_s4[count];
	uint16_t s2s_elapsed_hi[count];
	uint32_t s2s_elapsed_lo[count];
	uint32_t s2s_upreqdelay[count];
	uint32_t s2s_reqegts_lo[count], s2s_reqigts_lo[count];
	uint16_t s2s_reqegts_hi[count], s2s_reqigts_hi[count];
	uint16_t s2s_macts_hi[count];
	uint32_t s2s_macts_lo[count];
	uint16_t s2s_egts_hi[count];
	uint32_t s2s_egts_lo[count];
	uint32_t reference_hi[count], reference_lo[count];
	uint16_t now_igts_hi[count];
	uint32_t now_igts_lo[count];
	uint16_t now_macts_hi[count];
	uint32_t now_macts_lo[count];
	uint32_t offset_hi[count], offset_lo[count];
	uint32_t resp_qdepth[count], resp_qdelta[count];
  uint32_t capture_resp_tx[count];
  uint32_t reqDelayV[count];
	bf_dev_port_t reqport = 160;
	bf_dev_port_t respport = 176;
	uint64_t capture_req_ts;
	uint64_t capture_resp_ts;
	bool ts_valid1, ts_valid2;
	int ts_id1, ts_id2;
  uint32_t test1[count], test2[count];
	p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
	cp_flag[0] = 0;
	int i=1; // pipe
	int e=0;
	int s5log = 1;
	int s1log = 1;
	int s2log = 1;
	while(1) {
		p4_pd_dejavu_register_read_timesyncs2s_cp_flag(sess_hdl, p4_dev_tgt, 0, REGISTER_READ_HW_SYNC, cp_flag, &count);
		if (cp_flag[i] == 0) {
			continue;
		}
    //printf("Got a hit . %d\n", cp_flag[i]);
    uint64_t global_ts_ns_bef, global_ts_ns_aft, baresync_ts_ns;
    bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_bef, &baresync_ts_ns);

		switch(cp_flag[i]) {
      case 0x1:
        reqport  = 162; // Tofino1
        respport = 178;
        break;
      case 0x2:
        reqport  = 163; // Tofino1
        respport = 179;
        break;
      case 0x3:
    		reqport  = 177; // Tofino1
    		respport = 161;
    		break;
      case 0x4:
      	reqport  = 140; // Tofino1
      	respport = 136; // Tofino2
      	break;
      case 0x5:
        reqport  = 176; // Tofino1
        respport = 160;
        break;
      case 0x8:
  			reqport  = 177; // Tofino2
  			respport = 161;
  			break;
      case 0x9:
    		reqport  = 162; // Tofino2
    		respport = 178;
    		break;
      case 0x6:
        reqport  = 160; // Tofino1
        respport = 176;
        break;
      case 0x7:
        reqport  = 163; // Tofino1
        respport = 179;
        break;
      default:
        printf("Unexpected Case(%d)!\n", cp_flag[i]);
        return;
		}
		// First need to flush all
		int switch_id = cp_flag[i];
		bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, reqport, &capture_req_ts, &ts_valid1, &ts_id1);
    //printf("ts_valid=%d\n", ts_valid1);
    //nanosleep(&tsp, NULL); // Hack to address the bug

		//printf("======================Reply Received on Switch(%d)=========================\n", switch_id);

		p4_pd_dejavu_register_read_timesyncs2s_reference_hi(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_reference_hi, &count);
		p4_pd_dejavu_register_read_timesyncs2s_reference_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_reference_lo, &count);
		p4_pd_dejavu_register_read_timesyncs2s_elapsed_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_elapsed_lo, &count);
		p4_pd_dejavu_register_read_timesyncs2s_macts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_macts_lo, &count);
		p4_pd_dejavu_register_read_timesyncs2s_egts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, s2s_egts_lo, &count);
    p4_pd_dejavu_register_read_timesyncs2s_capture_tx(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, capture_resp_tx, &count);
		p4_pd_dejavu_register_read_timesyncs2s_now_macts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, now_macts_lo, &count);
		p4_pd_dejavu_register_read_timesyncs2s_igts_hi(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, now_igts_hi, &count);
		p4_pd_dejavu_register_read_timesyncs2s_igts_lo(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, now_igts_lo, &count);

		uint64_t s2s_elapsed = 0;

		uint64_t now_igts = 0;
		now_igts = ((now_igts | now_igts_hi[i]) << 32) | now_igts_lo[i];

    uint64_t reference_ts = 0;
    reference_ts = ((reference_ts | s2s_reference_hi[i]) << 32) | s2s_reference_lo[i];
    uint32_t s2s_reference_hi_r = reference_ts / max_ns;
    uint32_t s2s_reference_lo_r = reference_ts % max_ns;
    //printf("reference_ts(DPTP)   = %u s, reference_ts(DPTP)   = %u ns\n",
    // s2s_reference_hi[i], s2s_reference_lo[i]);
    // printf("ig_ts(DPTP)   = %u s, ig_ts(DPTP)   = %u ns\n",
    //  s2s_elapsed_hi[i], s2s_elapsed_lo[i]);
    //printf("time_r(DPTP)   = %u s, time_r(DPTP)  = %u ns\n", s2s_reference_hi_r, s2s_reference_lo_r);


    uint32_t test_ref_elapsed_hi = s2s_reference_hi[i] + s2s_elapsed_hi[i];
    uint32_t test_ref_elapsed_lo = s2s_reference_lo[i] + s2s_elapsed_lo[i];
    // if (s2s_reference_lo[i] < s2s_elapsed_lo[i]) {
    //   printf("Possible Overflow\n");
    // }

    capture_req_ts = capture_req_ts & 0xFFFFFFFF;
    capture_resp_ts = capture_resp_tx[i];


		int ReqMacDelay = s2s_elapsed_lo[i] - s2s_macts_lo[i];
		int replyQueing = s2s_egts_lo[i] - s2s_elapsed_lo[i];
		int respmacdelay = now_igts_lo[i] - now_macts_lo[i];
		int reqDelay =  capture_req_ts - s2s_reqigts_lo[i];
    // printf("capture_req_ts = %u\n", capture_req_ts);
    // printf("capture_tx = %u\n", capture_resp_ts);
    // printf("now_macts_lo = %u\n", now_macts_lo[i]);
		int respDelay = capture_resp_ts - s2s_elapsed_lo[i]; //s2s_egts;

		int latency_ig = now_igts_lo[i] - s2s_reqigts_lo[i];
    int latency_tx = now_macts_lo[i] - capture_req_ts;
    int respD = (latency_ig - ReqMacDelay - reqDelay - respDelay - respmacdelay)/2 + respDelay + respmacdelay;
    int respD_opt = (latency_tx - ReqMacDelay - respDelay)/2 + respDelay + respmacdelay;

    uint32_t calc_time_hi_dptp = s2s_reference_hi_r  + (respD_opt / max_ns);
		uint32_t calc_time_lo_dptp = s2s_reference_lo_r  + (respD_opt % max_ns);

    if (calc_time_lo_dptp >= max_ns) {
      calc_time_lo_dptp -= max_ns;
      calc_time_hi_dptp += 1;
    }

    uint32_t my_elp_hi = now_igts / max_ns;
    uint32_t my_elp_lo = now_igts % max_ns;

    // printf("s2s_elapsed_hi = %u, s2s_elapsed_lo= %u\n",
    //   s2s_elapsed_hi[i], s2s_elapsed_lo[i]);

		cp_flag[0] = 0;
		cp_flag[1] = 0;

		uint32_t ref_calc_time_hi  = calc_time_hi_dptp - my_elp_hi;
    uint32_t ref_calc_time_lo;
    if (calc_time_lo_dptp < my_elp_lo) {
      //printf("ref_calc_time_lo wrapup!\n");
      ref_calc_time_lo = (calc_time_lo_dptp + max_ns) - my_elp_lo;
      ref_calc_time_hi -= 1;
    } else {
      ref_calc_time_lo  = calc_time_lo_dptp - my_elp_lo;
    }

    reference_ts = ((uint64_t)ref_calc_time_hi * (uint64_t)max_ns) + ref_calc_time_lo;

    ref_calc_time_hi = (reference_ts >> 32) & 0xFFFFFFFF;

    ref_calc_time_lo = reference_ts & 0xFFFFFFFF;

    bool discard = false;
    if (respDelay < 0) {
      printf("***********************************Capture_tx Missed!*****************************\n");
      printf("ts_valid=%d\n", ts_valid1);
      printf("capture_req_ts = %u\n", capture_req_ts);
      printf("capture_tx = %u\n", capture_resp_ts);
      printf("now_macts_lo = %u\n", now_macts_lo[i]);
      printf("-------------------------------------------------\n");
      printf("                     Switch %d             \n", switch_id);
      printf("-------------------------------------------------\n");
      printf("Reply mac delay                   = %d ns\n", ReqMacDelay);
      printf("Reply Queing                      = %d ns\n", replyQueing);
      printf("Reply Egress Tx Delay             = %d ns\n", respDelay);
      printf("Reply mac delay                   = %d ns\n", respmacdelay);
      printf("Total RTT                         = %d ns\n", latency_tx);
      printf("-------------------------------------------------\n");
      bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, respport, &capture_resp_ts, &ts_valid1, &ts_id1);
      printf("Discarded : %u\n", capture_resp_ts & 0xFFFFFFFF);
      discard = true;
    }
    if (latency_tx > 10000 || latency_tx < -10000) {
      printf("***********************************Error is High!*****************************\n");
      printf("ts_valid=%d\n", ts_valid1);
      printf("capture_req_ts = %u\n", capture_req_ts);
      printf("capture_tx = %u\n", capture_resp_ts);
      printf("now_macts_lo = %u\n", now_macts_lo[i]);
      printf("-------------------------------------------------\n");
      printf("                     Switch %d             \n", switch_id);
      printf("-------------------------------------------------\n");
      printf("Reply mac delay                   = %d ns\n", ReqMacDelay);
      printf("Reply Queing                      = %d ns\n", replyQueing);
      printf("Reply Egress Tx Delay             = %d ns\n", respDelay);
      printf("Reply mac delay                   = %d ns\n", respmacdelay);
      printf("Total RTT                         = %d ns\n", latency_tx);
      printf("-------------------------------------------------\n");
      bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, reqport, &capture_req_ts, &ts_valid1, &ts_id1);
      printf("Discarded : %u\n", capture_req_ts & 0xFFFFFFFF);
      discard = true;
    }
    if (discard == true) {
      // Discard this interval, because something is wrong , maybe packet is missed!
      p4_pd_dejavu_register_write_timesyncs2s_cp_flag(sess_hdl, p4_dev_tgt, 0, cp_flag);
      p4_pd_complete_operations(sess_hdl);
      continue;
    }
    p4_pd_dejavu_register_write_reference_ts_hi(sess_hdl, p4_dev_tgt, switch_id, &ref_calc_time_hi);
		p4_pd_dejavu_register_write_reference_ts_lo(sess_hdl, p4_dev_tgt, switch_id, &ref_calc_time_lo);

		p4_pd_dejavu_register_write_timesyncs2s_cp_flag(sess_hdl, p4_dev_tgt, 0, cp_flag);
		p4_pd_complete_operations(sess_hdl);
		(void)p4_pd_commit_txn(sess_hdl, true);
    //printf("ReqDelay = %u ns\n", reqDelayV[i]);

    //if (switch_id == 4) {
    //  printf("-------------------------------------------------\n");
    //  printf("                     Switch %d             \n", switch_id);
    //  printf("-------------------------------------------------\n");
    //  printf("Reply mac delay                   = %d ns\n", ReqMacDelay);
    //  printf("Reply Queing                      = %d ns\n", replyQueing);
    //  printf("Reply Egress Tx Delay             = %d ns\n", respDelay);
    //  printf("Reply mac delay                   = %d ns\n", respmacdelay);
    //  printf("Total RTT                         = %d ns\n", latency_tx);
    //  printf("-------------------------------------------------\n");
    //}

    if (switch_id < 4 || switch_id == 5) {
      p4_pd_dejavu_register_read_reference_ts_hi(sess_hdl, p4_dev_tgt, 4, REGISTER_READ_HW_SYNC, reference_hi_s4, &count);
      p4_pd_dejavu_register_read_reference_ts_lo(sess_hdl, p4_dev_tgt, 4, REGISTER_READ_HW_SYNC, reference_lo_s4, &count);
      uint64_t reference_ts_s4 = 0;
      reference_ts_s4 = ((reference_ts_s4 | reference_hi_s4[i]) << 32) | reference_lo_s4[i];
      uint32_t reference_hi_s4_r = reference_ts_s4 / max_ns;
      uint32_t reference_lo_s4_r = reference_ts_s4 % max_ns;
      uint32_t s4_time_hi = reference_hi_s4_r + my_elp_hi;
      uint32_t s4_time_lo = reference_lo_s4_r + my_elp_lo;
      if (s4_time_lo >= max_ns) {
      //  printf("s3_time_lo Wrapup!\n");
        s4_time_lo -= max_ns;
        s4_time_hi += 1;
      }
      int error = calc_time_lo_dptp - s4_time_lo;

      fprintf(fc_sxs4,"%d\n", calc_time_lo_dptp - s4_time_lo);
      fflush(fc_sxs4);

       //printf("calc_time_hi(S1)     = %u s, calc_time_lo(S1)     = %u ns\n", calc_time_hi_dptp, calc_time_lo_dptp);
      // printf("calc_time_hi(S4)     = %u s, calc_time_lo(S4)     = %u ns\n", s4_time_hi, s4_time_lo);
      //
    } else if (switch_id == 4) {
      // Below are for ground-truth timestamp
  		p4_pd_dejavu_register_read_reference_ts_hi(sess_hdl, p4_dev_tgt, DPTP_SWITCH5, REGISTER_READ_HW_SYNC, reference_hi_master, &count);
  		p4_pd_dejavu_register_read_reference_ts_lo(sess_hdl, p4_dev_tgt, DPTP_SWITCH5, REGISTER_READ_HW_SYNC, reference_lo_master, &count);

      uint64_t reference_ts_master = 0;
      reference_ts_master = ((reference_ts_master | reference_hi_master[i]) << 32) | reference_lo_master[i];
      uint32_t reference_hi_master_r = reference_ts_master / max_ns;
      uint32_t reference_lo_master_r = reference_ts_master % max_ns;

  		uint32_t orig_time_hi = reference_hi_master_r + my_elp_hi;
  		uint32_t orig_time_lo = reference_lo_master_r + my_elp_lo;
      if (orig_time_lo >= max_ns) {
        orig_time_lo -= max_ns;
        orig_time_hi += 1;
      }
      fprintf(fc_s4s5,"%d\n", calc_time_lo_dptp - orig_time_lo);
      // printf("calc_time_hi(Master) = %u s, calc_time_lo(Master) = %u ns\n", orig_time_hi, orig_time_lo);
      // printf("calc_time_hi(DPTP)   = %u s, calc_time_lo(DPTP)   = %u ns\n", calc_time_hi_dptp, calc_time_lo_dptp);

      fflush(fc_s4s5);
      // s1log++;
    } else {
      // Below are for ground-truth timestamp
  		p4_pd_dejavu_register_read_reference_ts_hi(sess_hdl, p4_dev_tgt, DPTP_MASTER, REGISTER_READ_HW_SYNC, reference_hi_master, &count);
  		p4_pd_dejavu_register_read_reference_ts_lo(sess_hdl, p4_dev_tgt, DPTP_MASTER, REGISTER_READ_HW_SYNC, reference_lo_master, &count);

      uint64_t reference_ts_master = 0;
      reference_ts_master = ((reference_ts_master | reference_hi_master[i]) << 32) | reference_lo_master[i];
      uint32_t reference_hi_master_r = reference_ts_master / max_ns;
      uint32_t reference_lo_master_r = reference_ts_master % max_ns;

  		uint32_t orig_time_hi = reference_hi_master_r + my_elp_hi;
  		uint32_t orig_time_lo = reference_lo_master_r + my_elp_lo;
      if (orig_time_lo >= max_ns) {
        orig_time_lo -= max_ns;
        orig_time_hi += 1;
      }
      fprintf(fc_sxm,"%d\n", calc_time_lo_dptp - orig_time_lo);
      //printf("calc_time_hi(Master) = %u s, calc_time_lo(Master) = %u ns\n", orig_time_hi, orig_time_lo);
      //printf("calc_time_hi(DPTP)   = %u s, calc_time_lo(DPTP)   = %u ns\n", calc_time_hi_dptp, calc_time_lo_dptp);
      fflush(fc_sxm);
      // s1log++;
    }
    bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_aft, &baresync_ts_ns);
    //printf("time = %d\n", global_ts_ns_aft - global_ts_ns_bef);
    //printf("-------------------------------------------------\n");
	}
	fclose(fc_s4s5);
  fclose(fc_sxm);
  fclose(fc_sxs4);
}

void initialize_cpuif() {
	char *cpuif_netdev_name = "pcie0";
	char cpuif_knetdev_name[IFNAMSIZ];
	bf_knet_cpuif_t knet_cpuif_id;
	bf_knet_status_t status;

	status = bf_knet_cpuif_ndev_add(cpuif_netdev_name, cpuif_knetdev_name, &knet_cpuif_id);

	if (status == BF_KNET_E_NONE) {
		printf("Intf %s successfully created with id :%lu\n", cpuif_knetdev_name, knet_cpuif_id);
	} else {
		printf("Error Creating Interface, Error Id = %d (%s)\n", status, cpuif_knetdev_name);
	}
}
FILE *fp;

void send_bf_followup_packet(uint8_t *dstAddr, uint32_t capture_tx) {
	memcpy(dptp_followup_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
	dptp_followup_pkt.reference_ts_hi = htonl(capture_tx);
  memcpy(upkt, &dptp_followup_pkt, sz);

  if (bf_pkt_data_copy(bfpkt, upkt, sz) != 0) {
    printf("Failed data copy\n");
  }
  bf_status_t stat = bf_pkt_tx(0, bfpkt, tx_ring, (void *)bfpkt);
  if (stat  != BF_SUCCESS) {
    printf("Failed to send packet status=%s\n", bf_err_str(stat));
  }// else {
  //   printf("Packet sent successfully capture_tx=%x\n", htonl(capture_tx));
  // }
}

p4_pd_dejavu_timesync_inform_cp_digest_digest_notify_cb handle_timesync_followup_digest(p4_pd_sess_hdl_t sess_hdl,
        p4_pd_dejavu_timesync_inform_cp_digest_digest_msg_t *msg,
        void *callback_fn_cookie) {
  struct timespec time1, time2;
  uint64_t global_ts_ns, global_ts_ns_aft, baresync_ts_ns;
  uint32_t cpu, node;
	int count = 2;
	uint64_t capture_ts;
	bool ts_valid;
	p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
	uint32_t capture_ts_32;
	int ts_id;
  uint16_t num_entries = msg->num_entries;
  p4_pd_dejavu_timesync_inform_cp_digest_digest_entry_t digest;

	int i=0;
  int j=0;
	for (i=0;i< num_entries;i++) {
		uint16_t clientport = msg->entries[i].ig_intr_md_for_tm_ucast_egress_port;
		ts_valid = 0;
		int j = 1;
		while (ts_valid == 0) {
			bf_port_1588_timestamp_tx_get((bf_dev_id_t) 0, clientport, &capture_ts, &ts_valid, &ts_id);
			capture_ts_32 = capture_ts & 0xFFFFFFFF;
			j++;
 		}

		send_bf_followup_packet(msg->entries[i].ethernet_dstAddr, capture_ts_32);
    // uint64_t ingress_ts = 0;
    // for (j=0;j<6;j++) {
    //   ingress_ts = (ingress_ts | msg->entries[i].ig_intr_md_from_parser_aux_ingress_global_tstamp[j]) << 8;
    // }
    // ingress_ts  = ingress_ts >> 8;
	}
	p4_pd_dejavu_timesync_inform_cp_digest_notify_ack(sess_hdl, msg);
}

void store_snapshot_64(uint32_t ts_sec, uint32_t ts_nsec, uint64_t global_ts_ns_bef) {
	p4_pd_status_t status;
	uint64_t global_ts_ns_aft, baresync_ts_ns;
	p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
  int max_ns = 1000000000;
	uint64_t max_ns_32 = 4294967296;
  uint64_t reference_ts = 0;
	uint64_t global_ts_ns;
  uint64_t time_r = 0;
  uint32_t ts_sec_r;
  reference_ts = ((uint64_t)ts_sec * (uint64_t)max_ns) + ts_nsec;
  uint32_t ts_nsec_r;
	printf("****** Reset Global Offset ******\n");
	status = p4_pd_begin_txn(sess_hdl, true);
	if (status != 0) {
		printf("Failed to begin transaction err=%d\n", status);
		return;
	}

	bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_aft, &baresync_ts_ns);
  //global_ts_ns_aft = 1000000;
	printf("Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);
  printf("Time 64-bit = %lu\n", reference_ts);

  ts_sec = (reference_ts >> 32) & 0xFFFFFFFF;
  ts_nsec = reference_ts & 0xFFFFFFFF;

  printf("Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);


	uint32_t offset_t_lo = (uint32_t)global_ts_ns_aft & (uint32_t)0xFFFFFFFF;
	uint32_t offset_t_hi = (global_ts_ns_aft >> 32) & (uint32_t)0xFFFFFFFF;
  ts_sec  -= offset_t_hi;
  if (ts_nsec < offset_t_lo) {
    printf("Reference  wrapup!\n");
    uint64_t ts_nsec_big = (uint64_t)ts_nsec + (uint64_t)max_ns_32;
    printf("ts_nsec big = %lu\n", ts_nsec_big);
    ts_nsec = (uint32_t)(ts_nsec_big - (uint64_t)offset_t_lo);
    ts_sec -= 1;
  } else {
    ts_nsec  = ts_nsec - offset_t_lo;
  }

  p4_pd_dejavu_register_write_reference_ts_hi(sess_hdl, p4_dev_tgt, 0, &ts_sec);
  p4_pd_dejavu_register_write_reference_ts_lo(sess_hdl, p4_dev_tgt, 0, &ts_nsec);

  p4_pd_dejavu_register_write_reference_ts_hi(sess_hdl, p4_dev_tgt, DPTP_MASTER, &ts_sec);
  p4_pd_dejavu_register_write_reference_ts_lo(sess_hdl, p4_dev_tgt, DPTP_MASTER, &ts_nsec);

  p4_pd_dejavu_register_write_reference_ts_hi(sess_hdl, p4_dev_tgt, 2, &ts_sec);
  p4_pd_dejavu_register_write_reference_ts_lo(sess_hdl, p4_dev_tgt, 2, &ts_nsec);
	status = p4_pd_complete_operations(sess_hdl);
	(void)p4_pd_commit_txn(sess_hdl, true);
	printf("Adjusted offset = %lu\n", global_ts_ns_aft);
  printf("Adjusted offset_t_hi = %u, offset_t_lo = %u\n", offset_t_hi, offset_t_lo);
  printf("Setting Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);
  time_r = ((time_r | ts_sec) << 32) | ts_nsec;
	printf("***** Done ****\n");
}


void store_snapshot(uint32_t ts_sec, uint32_t ts_nsec, uint64_t global_ts_ns_bef) {
	p4_pd_status_t status;
	uint64_t global_ts_ns_aft, baresync_ts_ns;
	p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
	uint32_t max_ns = 1000000000;
	uint64_t global_ts_ns;

	printf("****** Reset Global Offset ******\n");
	status = p4_pd_begin_txn(sess_hdl, true);
	if (status != 0) {
		printf("Failed to begin transaction err=%d\n", status);
		return;
	}

	bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_aft, &baresync_ts_ns);
	printf("Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);


	uint32_t offset_lo = global_ts_ns_aft % max_ns;
	uint32_t offset_hi = global_ts_ns_aft / max_ns;
	ts_sec  -= offset_hi;
  if (ts_nsec < offset_lo) {
    printf("Reference  wrapup!\n");
    ts_nsec = (ts_nsec + max_ns) - offset_lo;
    ts_sec -= 1;
  } else {
    ts_nsec  = ts_nsec - offset_lo;
  }
	p4_pd_dejavu_register_write_reference_ts_hi(sess_hdl, p4_dev_tgt, 0, &ts_sec);
	p4_pd_dejavu_register_write_reference_ts_lo(sess_hdl, p4_dev_tgt, 0, &ts_nsec);

	status = p4_pd_complete_operations(sess_hdl);
	(void)p4_pd_commit_txn(sess_hdl, true);
	printf("Setting Time tv_sec = %u, tv_nsec = %u\n", ts_sec, ts_nsec);
	printf("Adjusted offset_hi = %u, offset_lo = %u\n", offset_hi, offset_lo);
	printf("***** Done ****\n");
}

void snapshot_reference() {
	struct timespec tsp;
	bf_status_t status;
	uint64_t global_ts_ns_bef, baresync_ts_ns;
	status = bf_ts_global_baresync_ts_get((bf_dev_id_t) 0, &global_ts_ns_bef, &baresync_ts_ns);
	if (status != 0) {
		printf("Failed to get global ts.\n");
		return;
	}
	clock_gettime(CLOCK_REALTIME, &tsp);   //Call clock_gettime to fill tsp
	store_snapshot_64((uint32_t)tsp.tv_sec, (uint32_t)tsp.tv_nsec, global_ts_ns_bef);
}


void init_bf_switchd() {
  bf_switchd_context_t *switchd_main_ctx = NULL;
  char *install_dir;
  char target_conf_file[100];
  int ret;
	p4_pd_status_t status;
  install_dir = getenv("SDE_INSTALL");
  sprintf(target_conf_file, "%s/share/p4/targets/tofino/dejavu.conf", install_dir);

  /* Allocate memory to hold switchd configuration and state */
  if ((switchd_main_ctx = malloc(sizeof(bf_switchd_context_t))) == NULL) {
    printf("ERROR: Failed to allocate memory for switchd context\n");
    return;
  }

  memset(switchd_main_ctx, 0, sizeof(bf_switchd_context_t));
  switchd_main_ctx->install_dir = install_dir;
  switchd_main_ctx->conf_file = target_conf_file;
  switchd_main_ctx->skip_p4 = false;
  switchd_main_ctx->skip_port_add = false;
  switchd_main_ctx->running_in_background = true;
  switchd_main_ctx->dev_sts_port = THRIFT_PORT_NUM;
  switchd_main_ctx->dev_sts_thread = true;

  ret = bf_switchd_lib_init(switchd_main_ctx);
  printf("Initialized bf_switchd, ret = %d\n", ret);

	status = p4_pd_client_init(&sess_hdl);
	if (status == 0) {
		printf("Successfully performed client initialization.\n");
	} else {
		printf("Failed in Client init\n");
	}

}

void init_ports() {
  if (switchid == 1) {
    //system("bfshell -f ports-add-tofino1.txt");
  } else if (switchid == 2) {
    //system("bfshell -f ports-add-tofino2.txt");
  }
	system("echo exit\n");
}

void init_tables() {
  if (switchid == 1) {
    system("bfshell -f commands-newtopo-tofino1.txt");
  } else if (switchid == 2) {
    system("bfshell -f commands-newtopo-tofino2.txt");
  }
}


static bf_status_t switch_pktdriver_tx_complete(bf_dev_id_t device,
                                                bf_pkt_tx_ring_t tx_ring,
                                                uint64_t tx_cookie,
                                                uint32_t status) {

  //bf_pkt *pkt = (bf_pkt *)(uintptr_t)tx_cookie;
  //bf_pkt_free(device, pkt);
  return 0;
}


int pktcount = 0;
bf_status_t rx_packet_callback_old (bf_dev_id_t dev_id, bf_pkt *pkt, void *cookie, bf_pkt_rx_ring_t rx_ring) {
  int i;
  pktcount++;

  //if (pktcount % 100 == 0) {
  //  if (pkt->pkt_data[13] == 0x35) {
      printf("Digest received :  %d\n", pktcount);

      for (i=0;i<pkt->pkt_size;i++) {
        printf("%X ", pkt->pkt_data[i]);
      }
      printf("\n");
  //  }
  //}
  bf_pkt_free(dev_id, pkt);
  return BF_SUCCESS;
}
//pd forward mod_entry set_egr_f by_match_spec ig_intr_md_ingress_port 136 ethernet_dstAddr 0x3cfdfeb7e7f4 action_egress_spec 176 action_entry_version 2
//pd forward mod_entry set_egr_f by_match_spec ig_intr_md_ingress_port 137 ethernet_dstAddr 0x3cfdfeb7e7f5 action_egress_spec 178 action_entry_version 3

void set_network_update() {
  sleep(10);
  p4_pd_entry_hdl_t entry_hdl;
  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};

  p4_pd_dejavu_forward_match_spec_t match_spec1;
  p4_pd_dejavu_set_egr_f_action_spec_t action_spec1;
  p4_pd_dejavu_forward_match_spec_t match_spec2;
  p4_pd_dejavu_set_egr_f_action_spec_t action_spec2;
  uint8_t flow1[] = {0x3c, 0xfd, 0xfe, 0xb7, 0xe7, 0xf4};
  uint8_t flow2[] = {0x3c, 0xfd, 0xfe, 0xb7, 0xe7, 0xf5};
  match_spec1.ig_intr_md_ingress_port = 136;
  memcpy(match_spec1.ethernet_dstAddr, flow1, 6);
  action_spec1.action_egress_spec = 176;
  action_spec1.action_entry_version = 2;
  match_spec2.ig_intr_md_ingress_port = 137;
  memcpy(match_spec2.ethernet_dstAddr, flow2, 6);
  action_spec2.action_egress_spec = 178;
  action_spec2.action_entry_version = 3;
  p4_pd_dejavu_forward_table_add_with_set_egr_f(sess_hdl, p4_dev_tgt, &match_spec1, &action_spec1, &entry_hdl);
  p4_pd_dejavu_forward_table_add_with_set_egr_f(sess_hdl, p4_dev_tgt, &match_spec2, &action_spec2, &entry_hdl);
  printf("addded enries*********\n");
}
bool trigger_done = false;
int  entries_per_packet = 16;
int POST_TRIGGER_ENTRIES = 5000;

void send_precord_packet(int switch_id, uint8_t *switch_mac) {
  uint32_t count = 20; // TBH
  int tot = 2;
  uint32_t total_pkts;
  uint32_t util[tot];
  int i=0;
  bf_status_t stat;

  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};

  memcpy(precord_pkt.srcAddr, switch_mac, 6);
  memcpy(prpkt, &precord_pkt, sz);
  if (bf_pkt_data_copy(bfprecordpkt, prpkt, precord_sz) != 0) {
    printf("Failed data copy\n");
  }
  //p4_pd_dejavu_register_read_current_utilization(sess_hdl, p4_dev_tgt, switch_id, REGISTER_READ_HW_SYNC, util, &count);
  //total_pkts = util[1];
  total_pkts = 10000;//1000 + POST_TRIGGER_ENTRIES; // For testing
  printf("Total packets to be collected=%d\n", total_pkts);
  p4_pd_dejavu_register_write_collect_packets(sess_hdl, p4_dev_tgt, switch_id, &total_pkts);
  int total_precord_pkts = (total_pkts/entries_per_packet) + 1;
  printf("Total precord Packets for switch %d = %d\n",switch_id, total_precord_pkts);
  for (i = 0;i<total_precord_pkts;i++) {
    stat = bf_pkt_tx(0, bfprecordpkt, tx_ring, (void *)bfprecordpkt);
    if (stat  != BF_SUCCESS) {
      printf("Failed to send packet(4) status=%s\n", bf_err_str(stat));
    }
    usleep(1);
  }
}

void* start_collection(void* args) {
  uint8_t switch1[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  uint8_t switch2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
  uint8_t switch3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
  uint8_t switch4[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
  uint8_t switch5[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
  uint8_t switch6[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06};
  uint8_t switch7[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
  uint8_t switch8[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08};
  uint8_t switch9[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x09};
  uint8_t switch10[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};
  printf("Starting Collection.\n");
  sleep(5);
  if (strcmp(switchName, "tofino1") == 0) {
      send_precord_packet(1, switch1);
      send_precord_packet(2, switch2);
      send_precord_packet(3, switch3);
      send_precord_packet(4, switch4);
      send_precord_packet(5, switch5);

  } else {
    send_precord_packet(6, switch6);
    send_precord_packet(7, switch7);
    send_precord_packet(8, switch8);
    send_precord_packet(9, switch9);
    send_precord_packet(10, switch10);
  }
}

bf_status_t rx_packet_callback (bf_dev_id_t dev_id, bf_pkt *pkt, void *cookie, bf_pkt_rx_ring_t rx_ring) {
  int i;
  pktcount++;
  uint8_t srcAddr[6];
  uint32_t count = 20; // TBH
  int tot = 2;
  uint32_t total_pkts;
  uint32_t util[tot];
  uint32_t dis_collect = 0;
  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};

  pthread_t collection_thread;


  if (pkt->pkt_data[13] == 0x36) {
      printf("Trigger received :  %d\n", pktcount);

      for (i=0;i<pkt->pkt_size;i++) {
        printf("%X ", pkt->pkt_data[i]);
      }
      printf("\n");
      if  (trigger_done == true) {
        // Temporary for testing 1 switch
        bf_pkt_free(dev_id, pkt);
        return BF_SUCCESS;
      }
      printf("Sending precord packets to %d\n", srcAddr[5]);
      int total_precord_pkts;
      pthread_create(&collection_thread, NULL, start_collection, NULL);

      trigger_done = true;
  }
  bf_pkt_free(dev_id, pkt);
  return BF_SUCCESS;
}
void switch_pktdriver_callback_register(bf_dev_id_t device) {

  bf_pkt_tx_ring_t tx_ring;
  bf_pkt_rx_ring_t rx_ring;

  /* register callback for TX complete */
  for (tx_ring = BF_PKT_TX_RING_0; tx_ring < BF_PKT_TX_RING_MAX; tx_ring++) {
    bf_pkt_tx_done_notif_register(
        device, switch_pktdriver_tx_complete, tx_ring);
  }
  /* register callback for RX */
  for (rx_ring = BF_PKT_RX_RING_0; rx_ring < BF_PKT_RX_RING_MAX; rx_ring++) {
    if (bf_pkt_rx_register(device, rx_packet_callback, rx_ring, NULL) != BF_SUCCESS) {
      printf("rx reg failed for ring %d (**unregister other handler)\n", rx_ring);
    }
  }
}

void pkt_init() {
  uint8_t dstAddr[] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
  memcpy(tcp_pkt.ethdstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  tcp_pkt.ethtype = htons(0x0800);
  tcp_pkt.version_ihl = 0x40;
  tcp_pkt.protocol = 17;
  tcp_pkt.ipdstAddr = 0x0a00000a;
  tcp_pkt.ipsrcAddr = 0x0a000001;
  tcp_pkt.srcPort = 0xa;
  tcp_pkt.dstPort = 0xf;
  tcp_pkt.seqNo = 0x1;
  tcp_pkt.interval = 0x1;
  tcp_pkt.cwnd = 0;
  ppkt = (uint8_t *) malloc(tcp_sz);
  memcpy(ppkt, &tcp_pkt, tcp_sz);
}

void bftrigpkt_init () {
  int i=0;
  if (bf_pkt_alloc(0, &bftrigpkt, trig_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
  uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
  memcpy(trigger_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  memcpy(trigger_pkt.srcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  trigger_pkt.type = htons(0x1236);

  tpkt = (uint8_t *) malloc(trig_sz);
  memcpy(tpkt, &trigger_pkt, trig_sz);

  if (bf_pkt_is_inited(0)) {
    printf("DPTP Followup packet is initialized\n");
  }

  if (bf_pkt_data_copy(bftrigpkt, tpkt, trig_sz) != 0) {
    printf("Failed data copy\n");
  }
  // printf("Trigger packet init");
  // for (i=0;i<trig_sz;i++) {
  //   printf("%X ",bftrigpkt[i]);
  // }
  printf("\n");
}

void bfprecordpkt_init () {
  int i=0;
  if (bf_pkt_alloc(0, &bfprecordpkt, trig_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
  uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
  memcpy(precord_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  memcpy(precord_pkt.srcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  precord_pkt.type = htons(0x1235);

  prpkt = (uint8_t *) malloc(precord_sz);
  memcpy(prpkt, &precord_pkt, precord_sz);

  if (bf_pkt_is_inited(0)) {
    printf("Precord packet is initialized\n");
  }

  if (bf_pkt_data_copy(bfprecordpkt, prpkt, precord_sz) != 0) {
    printf("Failed data copy\n");
  }
  // printf("Trigger packet init");
  // for (i=0;i<trig_sz;i++) {
  //   printf("%X ",bftrigpkt[i]);
  // }
  printf("\n");
}

uint8_t switch1[]       = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
uint8_t switch1_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x01};
uint8_t switch2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
uint8_t switch6[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06};
uint8_t switch6_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x06};

uint8_t switch7[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07};

uint8_t switch3_port0[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03};
uint8_t switch3_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x03};

uint8_t switch4_port0[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
uint8_t switch4_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x04};
uint8_t switch4_port2[] = {0x00, 0x00, 0x00, 0x20, 0x00, 0x04};

uint8_t switch5_port0[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05};
uint8_t switch5_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x05};


uint8_t switch8_port0[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08};
uint8_t switch8_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x08};

uint8_t switch9_port0[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x09};
uint8_t switch9_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x09};
uint8_t switch9_port2[] = {0x00, 0x00, 0x00, 0x20, 0x00, 0x09};

uint8_t switch10_port0[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0A};
uint8_t switch10_port1[] = {0x00, 0x00, 0x00, 0x10, 0x00, 0x0A};
uint8_t switch10_port2[] = {0x00, 0x00, 0x00, 0x20, 0x00, 0x0A};


void dptp_requestpkt_init() {
  int i=0;
  int cookie;
  if (bf_pkt_alloc(0, &bfdptppkt1, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt2, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt3, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt4, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt5, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt6, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt7, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt8, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt9, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  if (bf_pkt_alloc(0, &bfdptppkt10, dptp_sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }

  dreqpkt1  = (uint8_t *) malloc(dptp_sz);
  dreqpkt2  = (uint8_t *) malloc(dptp_sz);
  dreqpkt3  = (uint8_t *) malloc(dptp_sz);
  dreqpkt4  = (uint8_t *) malloc(dptp_sz);
  dreqpkt5  = (uint8_t *) malloc(dptp_sz);
  dreqpkt6  = (uint8_t *) malloc(dptp_sz);
  dreqpkt7  = (uint8_t *) malloc(dptp_sz);
  dreqpkt8  = (uint8_t *) malloc(dptp_sz);
  dreqpkt9  = (uint8_t *) malloc(dptp_sz);
  dreqpkt10 = (uint8_t *) malloc(dptp_sz);

  dptp_request_pkt.type = htons(0x88f7);
  dptp_request_pkt.magic = htons(0x0002);
  dptp_request_pkt.command = DPTP_GEN_REQ;

  // Tofino1
  memcpy(dptp_request_pkt.dstAddr, switch4_port2, 6);
  memcpy(dptp_request_pkt.srcAddr, switch1_port1, 6);
  memcpy(dreqpkt1, &dptp_request_pkt, dptp_sz);

  memcpy(dptp_request_pkt.dstAddr, switch4_port1, 6);
  memcpy(dptp_request_pkt.srcAddr, switch2, 6);
  memcpy(dreqpkt2, &dptp_request_pkt, dptp_sz);

  //memcpy(dptp_request_pkt.dstAddr, switch5_port0, 6);
  memcpy(dptp_request_pkt.dstAddr, switch1, 6);
  memcpy(dptp_request_pkt.srcAddr, switch3_port1, 6);
  memcpy(dreqpkt3, &dptp_request_pkt, dptp_sz);

  memcpy(dptp_request_pkt.dstAddr, switch10_port2, 6);
  memcpy(dptp_request_pkt.srcAddr, switch4_port0, 6);
  memcpy(dreqpkt4, &dptp_request_pkt, dptp_sz);

  memcpy(dptp_request_pkt.dstAddr, switch3_port0, 6);
  memcpy(dptp_request_pkt.srcAddr, switch5_port0, 6);
  memcpy(dreqpkt5, &dptp_request_pkt, dptp_sz);
  // Tofino2

  memcpy(dptp_request_pkt.dstAddr, switch9_port2, 6);
  memcpy(dptp_request_pkt.srcAddr, switch6_port1, 6);
  memcpy(dreqpkt6, &dptp_request_pkt, dptp_sz);

  memcpy(dptp_request_pkt.dstAddr, switch9_port1, 6);
  memcpy(dptp_request_pkt.srcAddr, switch7, 6);
  memcpy(dreqpkt7, &dptp_request_pkt, dptp_sz);

  memcpy(dptp_request_pkt.dstAddr, switch6, 6);
  memcpy(dptp_request_pkt.srcAddr,  switch8_port0, 6);
  memcpy(dreqpkt8, &dptp_request_pkt, dptp_sz);

  memcpy(dptp_request_pkt.dstAddr, switch10_port1, 6);
  memcpy(dptp_request_pkt.srcAddr,  switch9_port0, 6);
  memcpy(dreqpkt9, &dptp_request_pkt, dptp_sz);
  if (bf_pkt_is_inited(0)) {
    printf("DPTP Request Packet is initialized\n");
  }
  if (bf_pkt_data_copy(bfdptppkt1, dreqpkt1, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt2, dreqpkt2, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt3, dreqpkt3, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt4, dreqpkt4, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt5, dreqpkt5, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt6, dreqpkt6, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt7, dreqpkt7, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt8, dreqpkt8, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt9, dreqpkt9, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
  if (bf_pkt_data_copy(bfdptppkt10, dreqpkt10, dptp_sz) != 0) {
    printf("Failed data copy\n");
  }
}

void dptp_followuppkt_init() {
  int i=0;
  int cookie;
  if (bf_pkt_alloc(0, &bfpkt, sz, BF_DMA_CPU_PKT_TRANSMIT_0) != 0) {
    printf("Failed bf_pkt_alloc\n");
  }
  uint8_t dstAddr[] = {0x3c, 0xfd, 0xfe, 0xad, 0x82, 0xe0};//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4};// {0xf4, 0xe7, 0xb7, 0xfe, 0xfd, 0x3c};
  uint8_t srcAddr[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x11};
  memcpy(dptp_followup_pkt.dstAddr, dstAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  memcpy(dptp_followup_pkt.srcAddr, srcAddr, 6);//{0x3c, 0xfd,0xfe, 0xb7, 0xe7, 0xf4}
  dptp_followup_pkt.type = htons(0x88f7);
  dptp_followup_pkt.magic = htons(0x0002);
  dptp_followup_pkt.command = DPTP_FOLLOWUP;
  upkt = (uint8_t *) malloc(sz);
  memcpy(upkt, &dptp_followup_pkt, sz);
  if (bf_pkt_is_inited(0)) {
    printf("bf_pkt is initialized\n");
  }
  if (bf_pkt_data_copy(bfpkt, upkt, sz) != 0) {
    printf("Failed data copy\n");
  }
}

int trigger_id = 1;
void send_trigger_packet() {
  int i=0;
  trigger_pkt.trigger_id = htonl(trigger_id);

  tpkt = (uint8_t *) malloc(trig_sz);
  memcpy(tpkt, &trigger_pkt, trig_sz);
  if (bf_pkt_data_copy(bftrigpkt, tpkt, trig_sz) != 0) {
    printf("Failed data copy\n");
  } else {
    printf("Data copied\n");
  }
  bf_status_t stat = bf_pkt_tx(0, bftrigpkt, tx_ring, (void *)bftrigpkt);
  if (stat  != BF_SUCCESS) {
    printf("Failed to send packet status=%s\n", bf_err_str(stat));
  }
  trigger_id++;
  // for (i=0;i<trig_sz;i++) {
  //   printf("%X ",bftrigpkt[i]);
  // }
  // printf("\n");
}

void* send_dptp_requests_s4(void *args) {
  while(1) {
    printf("Sending DPTP Packets Out..for switch %d\n", switchid);

    bf_status_t stat = bf_pkt_tx(0, bfdptppkt4, tx_ring, (void *)bfdptppkt4);
    if (stat  != BF_SUCCESS) {
      printf("Failed to send packet(4) status=%s\n", bf_err_str(stat));
    }
    sleep(1);
  }
}

void* send_dptp_requests(void *args) {
  struct timespec tsp;
  tsp.tv_sec = 1;
  tsp.tv_nsec = 0;//90000000;
  int sleep_time = 2000;
  printf("Sending DPTP Packets Out..for switch %d\n", switchid);
  bf_status_t stat;
  int i=0;
  while (1) {
    if (switchid == 1) {
      stat = bf_pkt_tx(0, bfdptppkt4, tx_ring, (void *)bfdptppkt4);
      if (stat  != BF_SUCCESS) {
       printf("Failed to send packet(4) status=%s\n", bf_err_str(stat));
      }
      //nanosleep(&tsp, NULL);
      usleep(sleep_time);
      i++;
      stat = bf_pkt_tx(0, bfdptppkt1, tx_ring, (void *)bfdptppkt1);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(1) status=%s\n", bf_err_str(stat));
      }
      usleep(sleep_time);
      stat = bf_pkt_tx(0, bfdptppkt3, tx_ring, (void *)bfdptppkt3);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(4) status=%s\n", bf_err_str(stat));
      }
      usleep(sleep_time);
      stat = bf_pkt_tx(0, bfdptppkt2, tx_ring, (void *)bfdptppkt2);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(2) status=%s\n", bf_err_str(stat));
      }
      usleep(sleep_time);
      stat = bf_pkt_tx(0, bfdptppkt5, tx_ring, (void *)bfdptppkt5);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(5) status=%s\n", bf_err_str(stat));
      }
      usleep(sleep_time);
    } else if (switchid == 2) {
      //printf("Sending Packets..\n");
      stat = bf_pkt_tx(0, bfdptppkt9, tx_ring, (void *)bfdptppkt9);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(9) status=%s\n", bf_err_str(stat));
      }
      sleep(1);
      stat = bf_pkt_tx(0, bfdptppkt6, tx_ring, (void *)bfdptppkt6);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(6) status=%s\n", bf_err_str(stat));
      }
      sleep(1);
      stat = bf_pkt_tx(0, bfdptppkt7, tx_ring, (void *)bfdptppkt7);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(7) status=%s\n", bf_err_str(stat));
      }
      sleep(1);
      stat = bf_pkt_tx(0, bfdptppkt8, tx_ring, (void *)bfdptppkt8);
      if (stat  != BF_SUCCESS) {
        printf("Failed to send packet(8) status=%s\n", bf_err_str(stat));
      }
      sleep(1);
    }
  }
}

void* send_trigger(void *args) {
    printf("Sending IPv4/UDP Packets Out..\n");
    int i=1;
    sleep(1);
    while (1) {
      //send_trigger_packet();
      sleep(20);
      printf("****************************Sending Trigger******************************\n");
      send_trigger_packet();
    }
}

void* tester_thread(void *args) {
  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
  uint32_t collect[2];
  int count = 2;
  while (1) {
    p4_pd_dejavu_register_read_collect_packets(sess_hdl, p4_dev_tgt, 1, REGISTER_READ_HW_SYNC, collect, &count);
    if (collect[1] < 4) {
      printf("collect packets= %u\n", collect[1]);
    }
  }
}

void pktgen_init() {
  pkt_init();
  struct p4_pd_pktgen_app_cfg lcounter_app_cfg;
  uint16_t pkt_offset = 0;
  p4_pd_dev_target_t p4_pd_device;
  p4_pd_device.device_id = 0;
  p4_pd_device.dev_pipe_id = PD_DEV_PIPE_ALL;
  int buffer_len = 100;//(sz < 64)? 64:sz;
  p4_pd_status_t pd_status;

  pd_status = p4_pd_pktgen_enable(sess_hdl,0, 196);
  //pd_status = p4_pd_pktgen_enable(sess_hdl,0, 68);

  if (pd_status != 0) {
    printf("Failed to enable pktgen status = %d!!\n", pd_status);
    return;
  }
  lcounter_app_cfg.trigger_type = PD_PKTGEN_TRIGGER_TIMER_PERIODIC;
  lcounter_app_cfg.batch_count = 0;
  lcounter_app_cfg.packets_per_batch = 1;
  lcounter_app_cfg.pattern_value = 0;
  lcounter_app_cfg.pattern_mask = 0;
  lcounter_app_cfg.timer_nanosec = PACKETGEN_GAP;//100000;
  lcounter_app_cfg.ibg = 0;
  lcounter_app_cfg.ibg_jitter = 0;
  lcounter_app_cfg.ipg = 0  ;
  lcounter_app_cfg.ipg_jitter = 0;
  lcounter_app_cfg.source_port = 0;
  lcounter_app_cfg.increment_source_port = 0;
  lcounter_app_cfg.pkt_buffer_offset = 0;
  lcounter_app_cfg.length = buffer_len;
  pd_status = p4_pd_pktgen_cfg_app(sess_hdl,
                                   p4_pd_device,
                                   P4_PKTGEN_APP_LCOUNTER,
                                   lcounter_app_cfg);
  if (pd_status != 0) {
    printf(
        "pktgen app configuration failed "
        "for app %d on device %d : %s (pd: 0x%x)\n",
        P4_PKTGEN_APP_LCOUNTER,
        0, pd_status);
    return;
  }
  pd_status = p4_pd_pktgen_write_pkt_buffer(sess_hdl, p4_pd_device, pkt_offset, buffer_len, ppkt);
  if (pd_status != 0) {
    printf("Pktgen: Writing Packet buffer failed!\n");
    return;
  }
  p4_pd_complete_operations(sess_hdl);
  pd_status = p4_pd_pktgen_app_enable(sess_hdl, p4_pd_device, P4_PKTGEN_APP_LCOUNTER);

  if (pd_status != 0) {
    printf("Pktgen : App enable Failed!\n");
    return;
  }
  printf("Pktgen: Success!!\n");
}

p4_pd_mirror_session_info_t mirror_info_pipe1;
p4_pd_mirror_session_info_t mirror_info_pipe2;

#define MAX_PRECORD_PKTSIZE 44
// In Bytes. Calculated as :
// 14 (Eth) + 8 (PrecordHead) + 16(Precord) * MAX_PRECORDS
// 14 + 8 + (16*2) = 302
void init_recirc(void) {
  mirror_info_pipe1.type = 0;
  mirror_info_pipe1.dir = PD_DIR_BOTH;
  mirror_info_pipe1.id = 1;
  mirror_info_pipe1.egr_port = 196;
  mirror_info_pipe1.egr_port_v = 1;
  mirror_info_pipe1.max_pkt_len = MAX_PRECORD_PKTSIZE;
  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};

  p4_pd_status_t status = p4_pd_mirror_session_create(sess_hdl, p4_dev_tgt, &mirror_info_pipe1);
  printf("Created mirror session, status=%d\n", status);
}

#define BCAST_GRP 1

#define MAKE_288_PORT(pipe, l_port) (72 * pipe + l_port)
#define DEV_PORT_TO_PIPE(x) (((x) >> 7) & 3)
#define DEV_PORT_TO_LOCAL_PORT(x) ((x)&0x7F)

void init_broadcast(void) {
  p4_pd_status_t status;
  p4_pd_entry_hdl_t grp_hdl;
  p4_pd_entry_hdl_t node_hdl;
  p4_pd_sess_hdl_t mc_sess_hdl;
  int i = 0;
  // uint8_t port_map[] = {0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3 };
  // uint8_t lag_map[] = {};
  bf_dev_port_t dev_port_map[] =  {129, 140, 136, 145, 192, 0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3 };
  uint8_t port_map[288 / 8 + 1], lag_map[288 / 8 + 1];
  int index = 0;

  memset(&port_map, 0, sizeof(port_map));
  memset(&lag_map, 0, sizeof(lag_map));

  for (i = 0; i < sizeof(dev_port_map) ; i++) {
      index = MAKE_288_PORT(DEV_PORT_TO_PIPE(dev_port_map[i]), DEV_PORT_TO_LOCAL_PORT(dev_port_map[i]));
      port_map[index / 8] = (port_map[index / 8] | (1 << (index % 8))) & 0xFF;
  }

  status = p4_pd_mc_create_session(&mc_sess_hdl);
  printf("Created session, status=%d\n", status);
  status = p4_pd_mc_mgrp_create(mc_sess_hdl, 0, BCAST_GRP, &grp_hdl);
  printf("Created mgrp, status=%d\n", status);
  status = p4_pd_mc_node_create(mc_sess_hdl, 0, 0, &port_map, &lag_map, &node_hdl);
  printf("Created node, status=%d\n", status);
  status = p4_pd_mc_associate_node(mc_sess_hdl, 0, grp_hdl, node_hdl, 0, false);
  printf("Associated node, status=%d\n", status);
}

#define MAX_LINKS 512
int PRECORD_DURATION = 1000000;

void lpf_init () {
  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
  p4_pd_lpf_spec_t lpf_spec;
// //
 p4_pd_status_t status ;
  int i=0;
  lpf_spec.gain_decay_separate_time_constant = false;
  lpf_spec.time_constant = 10000; //1 s
  lpf_spec.output_scale_down_factor = 0;
  lpf_spec.lpf_type = PD_LPF_TYPE_RATE;// This calculates the aggreagate
  for (i=0;i<MAX_LINKS;i++) {
   status = p4_pd_dejavu_lpf_set_current_utilization_bps(sess_hdl, p4_dev_tgt, i, &lpf_spec);
    //status = p4_pd_dejavu_lpf_set_avg_qdepth(sess_hdl, p4_dev_tgt, i, &lpf_spec);
  }
  printf ("Set lpf status = %d\n", status);
}

void register_learn () {
	p4_pd_status_t status = 0;
  int pri = 7;
	void *cb_fun_cookie = NULL;
  status = p4_pd_dejavu_timesync_inform_cp_digest_register(sess_hdl, (uint8_t)0,
         (p4_pd_dejavu_timesync_inform_cp_digest_digest_notify_cb)handle_timesync_followup_digest,
         cb_fun_cookie);
  if (status != 0) {
    printf("Error registering learning module, err =%d\n", status);
  }

  // p4_pd_tm_set_q_sched_priority(0, 196, 0, pri);

  // status = p4_pd_dejavu_collect_digest_register(sess_hdl, (uint8_t)0,
  //         (p4_pd_dejavu_collect_digest_digest_notify_cb)handle_collect_digest,
  //         cb_fun_cookie);
  // if (status != 0) {
  //    printf("Error registering learning module, err =%d\n", status);
  // }
  fp = fopen("timesync-learn.log","w");
  p4_pd_dejavu_set_learning_timeout(sess_hdl, (uint8_t)0, 0);
}

void getSwitchName () {
  FILE *f = fopen("/etc/hostname","r");
  fscanf(f, "%s", switchName);
  if (strcmp(switchName, "tofino1") == 0) {
    switchid = 1;
  } else if (strcmp(switchName, "tofino2") == 0) {
    switchid = 2;
  }
  printf("Detected running on Tofino%d\n", switchid);
}
int WINDOW_CAPACITY_SWITCHES = 10000;
int FIN_TOFINO1 = 5;
int FIN_TOFINO2 = 10;
void init_stat_index () {
  uint32_t start_index = 0;
  uint32_t s1hash = 0;
  uint32_t s2hash = 1073741823;
  uint32_t s6hash = 2147483646;
  uint32_t s7hash = 3221225469;
  p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
  int i =0;
  uint32_t duration = POST_TRIGGER_ENTRIES;

  for (i=1;i<= FIN_TOFINO1;i++) {
    //p4_pd_dejavu_register_write_read_index(sess_hdl, p4_dev_tgt, i, &start_index);
    p4_pd_dejavu_register_write_write_index(sess_hdl, p4_dev_tgt, i, &start_index);
    start_index += WINDOW_CAPACITY_SWITCHES;
    p4_pd_dejavu_register_write_post_trigger(sess_hdl, p4_dev_tgt, i, &duration);

    //p4_pd_dejavu_register_write_precord_duration(sess_hdl, p4_dev_tgt, i, &PRECORD_DURATION);
  }
  start_index = 0;
  for (i=6;i<= FIN_TOFINO2;i++) {
    //p4_pd_dejavu_register_write_read_index(sess_hdl, p4_dev_tgt, i, &start_index);
    p4_pd_dejavu_register_write_write_index(sess_hdl, p4_dev_tgt, i, &start_index);
    start_index += WINDOW_CAPACITY_SWITCHES;
    p4_pd_dejavu_register_write_post_trigger(sess_hdl, p4_dev_tgt, i, &duration);
    //p4_pd_dejavu_register_write_precord_duration(sess_hdl, p4_dev_tgt, i, &PRECORD_DURATION);
  }
  p4_pd_dejavu_register_write_myhasher(sess_hdl, p4_dev_tgt, 1, &s1hash);
  p4_pd_dejavu_register_write_myhasher(sess_hdl, p4_dev_tgt, 2, &s2hash);
  p4_pd_dejavu_register_write_myhasher(sess_hdl, p4_dev_tgt, 6, &s6hash);
  p4_pd_dejavu_register_write_myhasher(sess_hdl, p4_dev_tgt, 7, &s7hash);
  uint32_t trigger_theshold = 10000;// 10us//1187500000; //0.95
  p4_pd_dejavu_register_write_queue_trigger_threshold(sess_hdl, p4_dev_tgt,0 , &trigger_theshold);

	p4_pd_complete_operations(sess_hdl);
}

int main (int argc, char **argv) {
	init_bf_switchd();
  getSwitchName();

	init_tables();

	init_ports();
	pthread_t era_thread;
	pthread_t timesyncs2s_thread;
  pthread_t trigger_thread;
  pthread_t dptp_thread;
  pthread_t dptp_thread_spl;
  pthread_t test_thread;
  pthread_t qdepth_thread;

	printf("Starting DejaVu Control Plane Unit ..\n");
	// Thread to monitor the Global Timestamp for wrap over, and increment Era
	pthread_create(&era_thread, NULL, monitor_global_ts, NULL);
	pthread_create(&timesyncs2s_thread, NULL, monitor_timesynctopo_64, NULL);
	switch_pktdriver_callback_register(0);
  dptp_followuppkt_init();
  dptp_requestpkt_init();
  lpf_init();
  init_recirc();
	register_learn();
	snapshot_reference();
  init_broadcast();

  // Packet Initialization for trigger test packets, and precordcollect packets
  bftrigpkt_init();
  bfprecordpkt_init();
  // Below function is for initializing array index for virtual switches.
  init_stat_index();
  //pthread_create(&trigger_thread, NULL, send_trigger, NULL);
  //pthread_create(&dptp_thread_spl, NULL, send_dptp_requests_s4, NULL);
  sleep(3);
  pthread_create(&dptp_thread, NULL, send_dptp_requests, NULL);

    //pktgen_init();
    //pthread_create(&test_thread, NULL, tester_thread, NLL);
  	// Hope this never hits. Wait indefinitely for threads to finish.
    // Below Thread is for mesuring impact of precord
    //pthread_create(&qdepth_thread, NULL, monitor_precord_qdepth, NULL);

  // Enable below for Network Update Test
  //set_network_update();
	pthread_join(era_thread, NULL);
	return 0;
}
