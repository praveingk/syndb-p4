/*
 * SyNDB - Synchronized network monitoring & debugging
 * Tables, actions, registers, etc 
 */

#define CPU 192
#define TOTAL_SNAP_PKTS 10
#define BCAST_GRP 1

#define REPLAY_DURATION 1000000000
#define TRIGGER_CLONE 1
#define PRECORD_CLONE 2

/* Field list to be carried to clone pkt */
field_list clone_pkt_fields {
    mdata.switch_id;
    mdata.dptp_now_lo;
    mdata.clone_type;
}
/* Field list for collection off digest */
field_list collect_digest {
    mdata.switch_id;
}
/* Field list for the tcp packet record hash */
field_list udp_hash_fields {
    udp.checksum;
    ethernet.srcAddr;
    ethernet.dstAddr;
    udp.dstPort;
}
field_list_calculation udp_hash {
    input { udp_hash_fields; }
    algorithm: identity;
    output_width: 32;
}
/* Field list for the ipv4 packet record hash */
field_list ipv4_hash_fields {
    ethernet.srcAddr;
    ethernet.dstAddr;
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
}

field_list_calculation ipv4_hash {
    input { ipv4_hash_fields; }
    algorithm: crc32;
    output_width: 32;
}
/* Field list for the dptp packet record hash */
field_list dptp_hash_fields {
    ethernet.srcAddr;
    ethernet.dstAddr;
    timesync.command;
}

field_list_calculation dptp_hash {
    input { dptp_hash_fields; }
    algorithm: crc32;
    output_width: 32;
}
register hack_for_dup_packet_reg  {
    width:8;
    instance_count:1;
}

blackbox stateful_alu poll_hack_for_dup_packet {
    reg: hack_for_dup_packet_reg;
    condition_lo : register_lo == 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value: 1;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value: 0;
    update_hi_1_value: register_lo;
    output_value: alu_hi;
    output_dst: mdata.hack_for_dup_packet;
}


register mycounter {
    width:32;
    instance_count:MAX_SWITCHES;
}

blackbox stateful_alu mycounter_update {
    reg:mycounter;
    update_lo_1_value: register_lo + 1;
    output_value : alu_lo;
    output_dst: mdata.pstat;
    //initial_register_lo_value : 100000;
}

register myhasher {
    width:32;
    instance_count:MAX_SWITCHES;
}

blackbox stateful_alu myhash_calc {
    reg: myhasher;
    condition_lo: register_lo >= mdata.hash_end;
    update_lo_1_predicate : not condition_lo;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate : condition_lo;
    update_lo_2_value : mdata.hash_start;//0;
    output_value : alu_lo;
    output_dst: mdata.phash;
    //initial_register_lo_value : 100000;
}
#define WINDOW_CAPACITY 1000
#define WINDOW_CAPACITY_SWITCHES 50000
register read_index {
    width: 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu read_index_get {
    reg: read_index;
    condition_lo: register_lo >= mdata.end_index;//WINDOW_CAPACITY - 1;
    update_lo_1_predicate : not condition_lo;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate : condition_lo;
    update_lo_2_value : mdata.start_index;//0;
    output_value : register_lo;
    output_dst : mdata.read_index;
}

register write_index {
    width: 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu write_index_get {
    reg: write_index;
    condition_lo: register_lo >= mdata.end_index;//WINDOW_CAPACITY - 1;
    update_lo_1_predicate : not condition_lo;
    update_lo_1_value: register_lo + 1;
    update_lo_2_predicate : condition_lo;
    update_lo_2_value : mdata.start_index;//0;
    output_value : register_lo;
    output_dst : mdata.write_index;
}

blackbox stateful_alu pread_index_get {
    reg: write_index;
    condition_lo: register_lo == mdata.start_index;//WINDOW_CAPACITY - 1;
    update_lo_1_predicate : not condition_lo;
    update_lo_1_value: register_lo - 1;
    update_lo_2_predicate : condition_lo;
    update_lo_2_value : mdata.end_index;//0;
    output_value : alu_lo;
    output_dst : mdata.read_index;
}

blackbox stateful_alu write_index_get_only {
    reg: write_index;
    output_value : register_lo;
    output_dst : mdata.write_index;
}
register checkpt_write_index {
    width : 32;
    instance_count : 1;
}

blackbox stateful_alu store_checkpt_write_index {
    reg: checkpt_write_index;
    update_lo_1_value: mdata.write_index;
}

blackbox stateful_alu get_checkpt_write_index {
    reg: checkpt_write_index;
    output_value : register_lo;
    output_dst : mdata.checkpt_write_index;
}
register window_size {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu incr_window_size {
    reg : window_size;
    //condition_hi : register_lo == WINDOW_CAPACITY;
    //update_lo_1_predicate : not condition_hi;
    update_lo_1_value : register_lo + 1;
}

blackbox stateful_alu decr_window_size {
    reg : window_size;
    condition_lo : register_lo > 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo - 1;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 0;
    output_value : alu_hi;
    output_dst : mdata.window_not_empty;
}

blackbox stateful_alu get_window_size {
    reg : window_size;
    output_value : register_lo;
    output_dst : mdata.window_residue;
}
register test1 {
    width : 32;
    instance_count : MAX_SWITCHES;
}


blackbox stateful_alu store_val_test1 {
    reg : test1;
    update_lo_1_value : eg_intr_md.pkt_length;//precordhead.tot_entries;//mdata.pkt;//1;//mdata.pkt;//eg_intr_md.pkt_length;//
}

register test2 {
    width : 32;
    instance_count : 1;
}

blackbox stateful_alu store_val_test2 {
    reg : test2;
    update_lo_1_value : register_lo + 1;//mdata.window_not_empty;//1;
}

register test3 {
    width : 32;
    instance_count : 1;
}

blackbox stateful_alu store_val_test3 {
    reg : test3;
    update_lo_1_value : register_lo + 1;
}

register window_residue {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu store_window_residue {
    reg : window_residue;
    update_lo_1_value : mdata.window_residue;
}

blackbox stateful_alu get_window_residue {
    reg : window_residue;
    condition_lo : register_lo > 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo - 1;
    output_value : register_lo;
    output_dst : mdata.window_residue;
}

register test4 {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu store_val_test4 {
    reg : test4;
    update_lo_1_value : register_lo + 1;
}

register precord_dur {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu precord_duration_store {
    reg : precord_dur;
    update_lo_1_value : mdata.precordhead_duration;
}

register test5 {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu store_val_test5 {
    reg : test5;
    update_lo_1_value :register_lo + 1;
}

register pstat {
    width : 32;
    instance_count : WINDOW_CAPACITY_SWITCHES;
}

blackbox stateful_alu pstat_store {
    reg : pstat;
    update_lo_1_value : mdata.pstat;
}

blackbox stateful_alu pstat_get {
    reg : pstat;
    output_value : register_lo;
    output_dst   : mdata.pstat;
}

register pstat2 {
    width : 32;
    instance_count : WINDOW_CAPACITY_SWITCHES;
}

blackbox stateful_alu pstat2_store {
    reg : pstat2;
    update_lo_1_value : mdata.pstat2;
}

blackbox stateful_alu pstat2_get {
    reg : pstat2;
    output_value : register_lo;
    output_dst   : mdata.pstat2;
}

register psip {
    width : 32;
    instance_count : WINDOW_CAPACITY_SWITCHES;
}

blackbox stateful_alu psip_store {
    reg : psip;
    update_lo_1_value : ipv4.srcAddr;//mdata.psip;
}

blackbox stateful_alu psip_get {
    reg : psip;
    output_value : register_lo;
    output_dst   : mdata.psip;
}

register phash {
    width : 32;
    instance_count : WINDOW_CAPACITY_SWITCHES;
}

blackbox stateful_alu phash_store {
    reg : phash;
    update_lo_1_value : mdata.phash;
}

blackbox stateful_alu phash_get {
    reg : phash;
    output_value : register_lo;
    output_dst   : mdata.phash;
}

register ptime_hi {
    width : 32;
    instance_count : WINDOW_CAPACITY;
}

blackbox stateful_alu time_hi_store {
    reg : ptime_hi;
    update_lo_1_value : mdata.dptp_now_hi;
}

blackbox stateful_alu time_hi_get {
    reg : ptime_hi;
    output_value : register_lo;
    output_dst   : mdata.ptime_hi;
}

register ptime_lo {
    width : 32;
    instance_count : WINDOW_CAPACITY_SWITCHES;
}

blackbox stateful_alu time_lo_store {
    reg : ptime_lo;
    update_lo_1_value : mdata.dptp_now_lo;
}

blackbox stateful_alu time_lo_get {
    reg : ptime_lo;
    output_value : register_lo;
    output_dst   : mdata.ptime_lo;
}

register pqueue {
    width : 32;
    instance_count : WINDOW_CAPACITY_SWITCHES;
}
blackbox stateful_alu queue_time_store {
    reg : pqueue;
    update_lo_1_value : mdata.pqueue;
}
blackbox stateful_alu queue_time_get {
    reg : pqueue;
    output_value : register_lo;
    output_dst   : mdata.pqueue;
}

register pqueuedepth {
    width : 32;
    instance_count : WINDOW_CAPACITY_SWITCHES;
}
blackbox stateful_alu queue_depth_store {
    reg : pqueuedepth;
    update_lo_1_value : eg_intr_md.enq_qdepth;
}
blackbox stateful_alu queue_depth_get {
    reg : pqueuedepth;
    output_value : register_lo;
    output_dst   : mdata.pqueuedepth;
}

register snap_pkts {
    width:32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu update_snap_pkts {
    reg: snap_pkts;
    condition_lo : register_lo < mdata.max_snap_pkts;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value: register_lo + 1;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 0;
    output_value : alu_hi;
    output_dst : mdata.clone_pkt;
}

blackbox stateful_alu decr_snap_pkts {
    reg:snap_pkts;
    condition_lo : register_lo > 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value: register_lo - 1;
}

register precord_duration {
    width:32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu precord_duration_check {
    reg: precord_duration;
    condition_lo : mdata.precordhead_duration > register_lo;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 0;
    output_value : alu_hi;
    output_dst : mdata.pde;
    initial_register_lo_value : REPLAY_DURATION;
}


register post_trigger {
    width:32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu count_post_trigger {
    reg: post_trigger;
    condition_lo : register_lo > 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo - 1;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 0;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 1;
    output_value : alu_hi;
    output_dst : mdata.stop_record;
    //Set Iniital value from control plane.initial_register_lo_value : REPLAY_DURATION;
}

register collect_in_progress {
    width : 8;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu collect_in_progress_on {
    reg : collect_in_progress;
    update_lo_1_value: 1;
}

blackbox stateful_alu collect_in_progress_off {
    reg : collect_in_progress;
    update_lo_1_value: 0;
    output_value : alu_lo;
    output_dst : mdata.cip;
}

blackbox stateful_alu collect_in_progress_get_off {
    reg : collect_in_progress;
    condition_lo : mdata.collect_pkts_done == 1;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value: 0;
    output_value : register_lo;
    output_dst : mdata.cip;
}

blackbox stateful_alu collect_in_progress_get {
    reg : collect_in_progress;
    output_value: register_lo;
    output_dst : mdata.cip;
}
//
// register precord_decide {
//     width : 32;
//     instance_count : 1;
// }
//
// blackbox stateful_alu do_precord_decide {
//     reg : precord_decide;
//     condition_lo : mdata.precordhead_duration > register_lo;
//     update_hi_1_predicate : condition_lo;
//     update_hi_1_value : 1;
//     update_hi_2_predicate : not condition_lo;
//     update_hi_2_value : 0;
//     output_value : alu_hi;
//     output_dst : mdata.snap_pkt_decide;
//     initial_register_lo_value : 2000000000;
// }
//
// register record_decide {
//     width : 32;
//     instance_count : 1;
// }
//
// blackbox stateful_alu do_precord_decide {
//     reg : record_decide;
//}

register current_trigger {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu check_current_trigger {
    reg : current_trigger;
    condition_lo : register_lo == 0;//trigger.trigger_id != register_lo;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : 1;//trigger.trigger_id;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 0;
    output_value : alu_hi;
    output_dst : mdata.trigger_act;
}

register current_trigger_egress {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu check_current_trigger_egress {
    reg : current_trigger_egress;
    condition_lo : trigger.trigger_id != register_lo;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : trigger.trigger_id;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 0;
    output_value : alu_hi;
    output_dst : mdata.trigger_act_egress;
}

blackbox stateful_alu get_current_trigger {
    reg : current_trigger_egress;
    update_lo_1_value : register_lo + 1;
    output_value : alu_lo;
    output_dst : mdata.trigger_id;
}

register collect_packets {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu collect_packets_clr {
    reg : collect_packets;
    update_lo_1_value : 0;
    output_value : alu_lo;
    output_dst : mdata.collect_packets;
}

blackbox stateful_alu collect_packets_incr {
    reg : collect_packets;
    condition_lo : register_lo < mdata.max_snap_pkts - 1;
    //update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo + 1;
    update_hi_1_predicate : not condition_lo;
    update_hi_1_value : 1;
    update_hi_2_predicate : condition_lo;
    update_hi_2_value : 0;
    output_value : alu_hi;
    output_dst : mdata.collect_pkts_done;
}

blackbox stateful_alu decr_collect_precords {
    reg : collect_packets;
    condition_lo : register_lo == 0;
    update_lo_1_predicate : not condition_lo;
    update_lo_1_value : register_lo - 1;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    output_value : alu_hi;
    output_dst : mdata.collect_done;
}

blackbox stateful_alu collect_packets_count {
    reg : collect_packets;
    condition_lo : register_lo == mdata.max_snap_pkts;
    update_lo_2_predicate : not condition_lo;
    update_lo_2_value : register_lo + 1;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 2;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 1;
    output_value : alu_hi;
    output_dst : mdata.collect_done;
}

register precord_qdepth {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu store_precord_qdepth {
    reg: precord_qdepth;
    update_lo_1_value : eg_intr_md.enq_qdepth;
}

register precord_qtime {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu store_precord_qtime {
    reg: precord_qtime;
    update_lo_1_value : mdata.pqueue;
}

register precord_max_qdepth {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu max_qdepth {
    reg: precord_max_qdepth;
    condition_lo : register_lo < eg_intr_md.enq_qdepth;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : eg_intr_md.enq_qdepth;
}

register precord_min_qdepth {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu min_qdepth {
    reg: precord_min_qdepth;
    condition_lo : register_lo > eg_intr_md.enq_qdepth;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : eg_intr_md.enq_qdepth;
    initial_register_lo_value : 0xFFFFFFFF;
}

register precord_avg_qdepth {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu store_precord_avg_qdepth {
    reg: precord_avg_qdepth;
    update_lo_1_value : mdata.avg_qdepth;
}

blackbox lpf avg_qdepth {
    filter_input: eg_intr_md.enq_qdepth;
    instance_count: MAX_LINKS;
}

register last_precord_time {
    width:32;
    instance_count : 1;
}
@pragma stateful_field_slice eg_intr_md_from_parser_aux.egress_global_tstamp 31 0
blackbox stateful_alu get_last_precord_time {
    reg: last_precord_time;
    update_lo_1_value: mdata.egress_timestamp_clipped;
    output_value: register_lo;
    output_dst:mdata.last_precord_time;
}

register precord_ipg {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu store_precord_ipg {
    reg: precord_ipg;
    update_lo_1_value : mdata.ipg;
}

register queue_trigger_threshold {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu check_queue_trigger_threshold {
    reg : queue_trigger_threshold;
    condition_lo : mdata.pqueue >= register_lo;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    update_hi_2_predicate : not condition_lo;
    update_hi_2_value : 0;
    output_value : alu_hi;
    output_dst : mdata.trigger_hit;
}
action do_hack_for_dup_packet () {
    poll_hack_for_dup_packet.execute_stateful_alu(0);
}

action do_forward_to_cpu() {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, 192);
}

action forward_to_collector(collector_mac, egress_spec) {
    modify_field(ethernet.etherType, ETHERTYPE_COLL);
    //modify_field(ethernet.srcAddr, 0x000000000001);
    modify_field(ethernet.dstAddr, collector_mac);
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action do_mark_last_precord () {
    //modify_field(precordhead.update_time,0);
    //generate_digest(FLOW_LRN_DIGEST_RCVR, collect_digest);
    modify_field(mdata.last_precord, 1);
}

action do_tag_last_precord () {
    modify_field(precordhead.update_time,0);
    //store_val_test1.execute_stateful_alu(0);
}
action do_mycounter() {
    mycounter_update.execute_stateful_alu(mdata.switch_id);
}


action do_signal_end () {
    modify_field(coal.coal_test, 1);
}

action do_set_max_snap_pkts (max_snap) {
    modify_field(mdata.max_snap_pkts, max_snap);
}

action do_set_precord_duration (precord_duration) {
    modify_field(mdata.precord_duration, precord_duration);
}
action do_set_max_precords (max_precords) {
    modify_field(mdata.max_precords, max_precords);
}

action do_check_current_snap_pkts () {
    update_snap_pkts.execute_stateful_alu(mdata.switch_id);
}

action do_decr_snap_pkts () {
    decr_snap_pkts.execute_stateful_alu(mdata.switch_id);
}

action discard_cp () {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, 192);
}

action discard_drop () {
    drop();
}

action do_reduce_snap_pkts () {
    decr_snap_pkts.execute_stateful_alu(mdata.switch_id);
}
action do_clone_pkt (session_id) {
    //store_val_test1.execute_stateful_alu(mdata.switch_id);
    clone_ingress_pkt_to_egress(session_id, clone_pkt_fields);
}

action do_trigger_condition_test () {
    //modify_field(mdata.trigger_hit, 1);
    check_queue_trigger_threshold.execute_stateful_alu(0);
}

action do_trigger_condition_pktcount () {
    modify_field(mdata.trigger_hit, 1);
}

action do_make_trigget_packet (session_id) {
    //store_val_test1.execute_stateful_alu(mdata.switch_id);
    modify_field(mdata.clone_type, TRIGGER_CLONE);
    clone_egress_pkt_to_egress(session_id, clone_pkt_fields);
    //store_val_test1.execute_stateful_alu(0);
}
action do_recirc_to_1 () {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, 196);
    modify_field(mdata.read_precord, 1);
}

action do_precordhead_duration_expiry () {
    precord_duration_check.execute_stateful_alu(mdata.switch_id);
    //modify_field(mdata.handle_precord, 1);
}

action do_check_trigger () {
    check_current_trigger.execute_stateful_alu(mdata.switch_id);
}

action do_check_trigger_egress () {
    check_current_trigger_egress.execute_stateful_alu(mdata.switch_id);
}

action do_broadcast () {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, BCAST_GRP);
    modify_field(ig_intr_md_for_tm.rid, 0);
}

action do_store_precord_duration () {
    precord_duration_store.execute_stateful_alu(mdata.switch_id);
}

action do_enable_collect_in_progress () {
    collect_in_progress_on.execute_stateful_alu(mdata.switch_id);
}

action do_calc_stat_index (start_index, end_index) {
    modify_field(mdata.start_index, start_index);
    modify_field(mdata.end_index, end_index);
}

action do_calc_hash_index (start_index, end_index) {
    modify_field(mdata.hash_start, start_index);
    modify_field(mdata.hash_end, end_index);
}


action do_get_disable_collect_in_progress () {
    collect_in_progress_get_off.execute_stateful_alu(mdata.switch_id);
}

action do_get_collect_in_progress () {
    collect_in_progress_get.execute_stateful_alu(mdata.switch_id);
}

action do_clear_collect_packets () {
    collect_packets_clr.execute_stateful_alu(mdata.switch_id);
}

action do_get_collect_packets () {
    collect_packets_incr.execute_stateful_alu(mdata.switch_id);
}

action do_check_if_collect_in_progress () {
    //TODO
}

table forward_to_cpu {
    actions {
        do_forward_to_cpu;
    }
    default_action : do_forward_to_cpu;
}

table hack_for_dup_packet {
    actions {
        do_hack_for_dup_packet;
    }
    default_action : do_hack_for_dup_packet;
}
//@pragma stage 3
table mycounter {
    reads {
        mdata.pkt_type: exact;
    }
    actions {
        do_mycounter;
        nop;
    }
    default_action : nop;
}

table signal_end {
    reads {
        mdata.new_ingress_count : exact;
    }
    actions {
        do_signal_end;
        nop;
    }
    default_action : nop;
}

table set_max_snap_pkts {
    actions {
        do_set_max_snap_pkts;
    }
    default_action : do_set_max_snap_pkts;
}

table set_precord_duration {
    actions {
        do_set_precord_duration;
    }
    default_action : do_set_precord_duration;
}
table set_max_precords {
    actions {
        do_set_max_precords;
    }
    default_action : do_set_max_precords;
}

@pragma stage 9
table check_current_snap_pkts {
    // reads {
    //     mdata.cip : exact;
    // }
    actions {
        do_check_current_snap_pkts;
        //nop;
    }
    default_action : do_check_current_snap_pkts;
}
@pragma stage 2
table decr_snap_pkts {
    actions {
        do_decr_snap_pkts;
    }
    default_action : do_decr_snap_pkts;
}
table clone_pkt {
    reads {
        mdata.clone_pkt : exact;
    }
    actions {
        do_clone_pkt;
        nop;
    }
    default_action : nop;
}



table recirc {
    actions {
        do_recirc_to_1;
    }
    default_action : do_recirc_to_1;
}


table calc_stat_index {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        do_calc_stat_index;
        nop;
    }
    default_action : nop;
}

table calc_hash_index {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        do_calc_hash_index;
        nop;
    }
    default_action : nop;
}
@pragma stage 7
table calc_precordhead_duration {
    reads {
        mdata.pkt_type : exact;
    }
    actions {
        do_calc_precordhead_duration;
        nop;
    }
    default_action : nop;//do_calc_precordhead_duration;
}
@pragma stage 8
table check_precordhead_duration {
    reads {
        mdata.pkt_type : exact;
    }
    actions {
        do_precordhead_duration_expiry;
        nop;
    }
    default_action : nop;//do_precordhead_duration_expiry;
}
@pragma stage 3
table check_trigger {
    reads {
        mdata.pkt_type : exact;
    }
    actions {
        do_check_trigger;
        nop;
    }
    default_action : nop;
}
table check_trigger_egress {
    reads {
        mdata.pkt_type : exact;
    }
    actions {
        do_check_trigger_egress;
        nop;
    }
    default_action : nop;
}
@pragma stage 10
table broadcast {
    reads {
        mdata.pkt_type : exact;
        mdata.trigger_act : exact;
    }
    actions {
        do_broadcast;
        nop;
    }
    default_action : nop;
}

//@pragma stage 4
table handle_precord {
    reads {
        mdata.pde : exact;
        mdata.cip : exact;
        //mdata.collect_done : exact;
        precordhead.residue : exact;
    }
    actions {
        discard_cp;
        discard_drop;
        do_recirc_to_1;
        forward_to_collector;
    }
    default_action : do_recirc_to_1;
    size : 10;
}

table handle_precord_collect {
    reads {
        mdata.collect_done : exact;
        precordhead.tot_entries : range;
    }
    actions {
        do_recirc_to_1;
        forward_to_collector;
    }
    default_action : do_recirc_to_1;
    size : 10;
}
@pragma stage 9
table reduce_snap_pkts {
    reads {
        mdata.pde : exact;
        mdata.cip : exact;
        //mdata.collect_done : exact;
        precordhead.residue :exact;
    }
    actions {
        do_reduce_snap_pkts;
        nop;
    }
    default_action : nop;
    size : 10;
}

table mark_last_precord {
    reads {
        mdata.collect_pkts_done : exact;
        //mdata.collect_done : exact;
        mdata.cip : exact;
    }
    actions {
        do_mark_last_precord;
        nop;
    }
    default_action : nop;
    size : 10;
}

table tag_last_precord {
    reads {
        mdata.last_precord   : exact;
        mdata.window_residue : exact;
    }
    actions {
        do_tag_last_precord;
        nop;
    }
    default_action : nop;
    size : 10;
}
table store_precord_duration {
    actions {
        do_store_precord_duration;
    }
    default_action : do_store_precord_duration;
}

@pragma stage 8
table enable_collect_in_progress {
    reads {
        mdata.trigger_act : exact;
    }
    actions {
        do_enable_collect_in_progress;
        nop;
    }
    default_action : nop;
}

@pragma stage 8
table get_disable_collect_in_progress {
    actions {
        do_get_disable_collect_in_progress;
    }
    default_action : do_get_disable_collect_in_progress;
}

@pragma stage 8
table get_collect_in_progress {
    actions {
        do_get_collect_in_progress;
    }
    default_action : do_get_collect_in_progress;
}

@pragma stage 7
table clear_collect_packets {
    reads {
        mdata.trigger_act : exact;
    }
    actions {
        do_clear_collect_packets;
        nop;
    }
    default_action : nop;
}

@pragma stage 7
table get_collect_packets {
    actions {
        do_get_collect_packets;
    }
    default_action : do_get_collect_packets;
}

table check_if_collect_in_progress {
    actions {
        do_check_if_collect_in_progress;
    }
    default_action : do_check_if_collect_in_progress;
}

action do_coalesce () {
    sample_e2e(1016, 8, coal);
}

action do_send_to_cpu () {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, CPU);
}
table coalesce {
    actions {
        do_coalesce;
    }
    default_action : do_coalesce;
}

table send_to_cpu {
    actions {
        do_send_to_cpu;
    }
    default_action : do_send_to_cpu;
}


action do_test1 () {
    modify_field(mdata.test1, 1);
    store_val_test1.execute_stateful_alu(0);
}

action do_test2 () {
    store_val_test2.execute_stateful_alu(0);
}

action do_test3 () {
    store_val_test3.execute_stateful_alu(0);
}

action do_test4 () {
    store_val_test4.execute_stateful_alu(mdata.switch_id);
}

action do_test5 () {
    store_val_test5.execute_stateful_alu(mdata.switch_id);
}

action do_store_stat () {
    pstat_store.execute_stateful_alu(mdata.write_index);
}

action do_store_stat2 () {
    pstat2_store.execute_stateful_alu(mdata.write_index);
}

action do_store_sip () {
    psip_store.execute_stateful_alu(mdata.write_index);
}
action do_get_stat () {
    pstat_get.execute_stateful_alu(mdata.read_index);
}

action do_get_stat2 () {
    pstat2_get.execute_stateful_alu(mdata.read_index);
}

action do_get_sip () {
    psip_get.execute_stateful_alu(mdata.read_index);
}

action do_store_hash () {
    phash_store.execute_stateful_alu(mdata.write_index);
}

action do_get_hash () {
    phash_get.execute_stateful_alu(mdata.read_index);
}

action do_store_queue_time () {
    queue_time_store.execute_stateful_alu(mdata.write_index);
}

action do_store_queue_depth () {
    queue_depth_store.execute_stateful_alu(mdata.write_index);
}

action do_store_queue_time_1 () {
    store_precord_qtime.execute_stateful_alu(mdata.switch_id);
}

action do_get_queue_time () {
    queue_time_get.execute_stateful_alu(mdata.read_index);
}

action do_get_queue_depth () {
    queue_depth_get.execute_stateful_alu(mdata.read_index);
}
action do_store_time_lo () {
    time_lo_store.execute_stateful_alu(mdata.write_index);
}

action do_get_time_lo () {
    time_lo_get.execute_stateful_alu(mdata.read_index);
}

action do_store_time_hi () {
    time_hi_store.execute_stateful_alu(mdata.write_index);
}

action do_get_time_hi () {
    time_hi_get.execute_stateful_alu(mdata.read_index);
}

action do_get_write_index () {
    write_index_get.execute_stateful_alu(mdata.switch_id);
}

action do_get_pread_index () {
    pread_index_get.execute_stateful_alu(mdata.switch_id);
}

action do_get_window_size_1 () {
    get_window_size.execute_stateful_alu(mdata.switch_id);
}
action do_store_checkpt_write_index () {
    store_checkpt_write_index.execute_stateful_alu(0);
}

action do_get_checkpt_write_index () {
    get_checkpt_write_index.execute_stateful_alu(0);
}

action do_get_read_index () {
    read_index_get.execute_stateful_alu(mdata.switch_id);
}

action do_add_precordhead (srcAddr) {
    remove_header(ipv4);
    remove_header(tcp);
    modify_field(ethernet.etherType, ETHERTYPE_SNAP);
    modify_field(ethernet.srcAddr, srcAddr);
    modify_field(precordhead.update_time, eg_intr_md_from_parser_aux.egress_global_tstamp);
    modify_field(precordhead.entries, 0);
    modify_field(precordhead.tot_entries, 0);
    modify_field(precordhead.residue, 0);
    //modify_field(precordhead.roll, 0);
    modify_field(mdata.pkt_type, PRECORD);
    add_header(precordhead);
    // push(precord, MAX_PRECORDS);
    // modify_field(precord[0].pstat, 0xFF);//mdata.pstat);
}

action do_add_trigger (srcAddr, dstAddr) {
    remove_header(ipv4);
    remove_header(tcp);
    remove_header(udp);
    modify_field(ethernet.srcAddr, srcAddr);
    modify_field(ethernet.dstAddr, dstAddr);
    modify_field(ethernet.etherType, ETHERTYPE_TRIG);
    modify_field(trigger.trigger_id, mdata.trigger_id);
    //modify_field(trigger.trigger_origin, mdata.switch_id);
    modify_field(trigger.trigger_hit_time, mdata.dptp_now_lo);
    add_header(trigger);
}

// action do_add_precord () {
//     add_header(precord);
//     modify_field(precord.phash, mdata.phash);
//     modify_field(precord.ptime_in, mdata.ptime_lo);
//     modify_field(precord.pstat, mdata.pstat);
//     modify_field(precord.pqueue, mdata.pqueue);
//
//     modify_field(precordhead.update_time, eg_intr_md_from_parser_aux.egress_global_tstamp);
//     add_to_field(precordhead.entries, 1);
//     //store_val_test3.execute_stateful_alu(mdata.switch_id);
// }
action do_add_precord () {
    push(precord, 1);
    modify_field(precord[0].phash, mdata.phash);
    modify_field(precord[0].ptime_in, mdata.ptime_lo);
    modify_field(precord[0].pstat, mdata.pstat);
    modify_field(precord[0].pstat2, mdata.pstat2);
    modify_field(precord[0].psip, mdata.psip);
    modify_field(precord[0].pqueue, mdata.pqueue);
    modify_field(precord[0].pqueuedepth, mdata.pqueuedepth);

    modify_field(precordhead.update_time, eg_intr_md_from_parser_aux.egress_global_tstamp);
    add_to_field(precordhead.entries, 1);
    add_to_field(precordhead.tot_entries, 1);
    //store_val_test3.execute_stateful_alu(mdata.switch_id);
}

action do_reset_precord_entries () {
    modify_field(precordhead.entries, 0);
    //add_to_field(precordhead.roll, 1);
}

action do_update_window_size () {
    incr_window_size.execute_stateful_alu(mdata.switch_id);
}

action do_get_window_size () {
    decr_window_size.execute_stateful_alu(mdata.switch_id);
}

action do_calc_precordhead_duration () {
    subtract(mdata.precordhead_duration, ig_intr_md_from_parser_aux.ingress_global_tstamp, precordhead.update_time);
}

action do_calc_queue_time () {
    subtract(mdata.pqueue, eg_intr_md_from_parser_aux.egress_global_tstamp, ig_intr_md_from_parser_aux.ingress_global_tstamp);
}

action do_get_window_residue_on_last () {
    subtract(mdata.window_residue, mdata.checkpt_write_index, mdata.read_index);
    //store_val_test3.execute_stateful_alu(0);
}

action do_store_window_residue () {
    store_window_residue.execute_stateful_alu(mdata.switch_id);
}

action do_act_on_residue () {
    //store_val_test2.execute_stateful_alu(0);
    modify_field(precordhead.residue, 1);
}

action do_act_on_last_residue () {
    //store_val_test2.execute_stateful_alu(0);
    modify_field(precordhead.residue, 0);
    modify_field(precordhead.update_time, 0);
}

action do_count_collect_packets () {
    collect_packets_count.execute_stateful_alu(mdata.switch_id);
}
action no_residue () {
    //store_val_test2.execute_stateful_alu(0);
    modify_field(precordhead.residue, 0);
}

action do_get_window_residue () {
    get_window_residue.execute_stateful_alu(mdata.switch_id);
}

action do_dptp_hash () {
    modify_field_with_hash_based_offset(mdata.phash, 0, dptp_hash, MAX_32BIT_SIZE);
}

action do_ipv4_hash () {
    modify_field_with_hash_based_offset(mdata.phash, 0, ipv4_hash, MAX_32BIT_SIZE);
}

action do_udp_hash () {
    modify_field_with_hash_based_offset(mdata.phash, 0, udp_hash, MAX_32BIT_SIZE);
}

action do_classify_switch_precord (switch_id) {
    modify_field(mdata.switch_id, switch_id);
}

action do_calc_precord_entries () {
    //shift_left(mdata.precord_entries, precordhead.roll, 1);
}

action do_get_trigger_id () {
    get_current_trigger.execute_stateful_alu(mdata.switch_id);
}

action do_store_qdepth () {
    store_precord_qdepth.execute_stateful_alu(mdata.switch_id);
}

action do_calc_avg_qdepth () {
    avg_qdepth.execute(mdata.avg_qdepth, 0);
}

action do_calc_max_qdepth () {
    max_qdepth.execute_stateful_alu(mdata.switch_id);
}

action do_calc_min_qdepth () {
    min_qdepth.execute_stateful_alu(mdata.switch_id);
}

action do_store_avg_qdepth () {
    store_precord_avg_qdepth.execute_stateful_alu(mdata.switch_id);
}

action do_check_total_precords () {
    modify_field(mdata.precord_entries_avail, 1);
}

action do_get_last_precord_time () {
    get_last_precord_time.execute_stateful_alu(0);
}

action do_calc_ipg () {
    subtract(mdata.ipg, mdata.egress_timestamp_clipped, mdata.last_precord_time);
}

action do_store_ipg () {
    store_precord_ipg.execute_stateful_alu(0);
}

action do_decr_precord_count () {
    decr_collect_precords.execute_stateful_alu(mdata.switch_id);
}

action do_assign_pstat () {
    //modify_field(mdata.pstat, udp.checksum);
    modify_field(mdata.pstat, mdata.cp_version);
}

action do_calc_phash () {
    myhash_calc.execute_stateful_alu(mdata.switch_id);
}

action do_update_packet_hash () {
    modify_field(udp.checksum, mdata.phash);
}

action do_assign_phash () {
    modify_field(mdata.phash, udp.checksum);
}

action calc_pstat_counter () {
    modify_field(udp.checksum, mdata.pstat);
}
action dont_classify () {
    modify_field(mdata.dont_record, 1);
}

action do_post_trigger_counter () {
    count_post_trigger.execute_stateful_alu(mdata.switch_id);
}
table itest1 {
    actions {
        do_test1;
    }
    default_action : do_test1;
}

table itest2 {
    actions {
        do_test2;
    }
    default_action : do_test2;
}

table itest3 {
    actions {
        do_test3;
    }
    default_action : do_test3;
}

table itest4 {
    actions {
        do_test4;
    }
    default_action : do_test4;
}

table itest5 {
    actions {
        do_test5;
    }
    default_action : do_test5;
}


table add_precordhead {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        do_add_precordhead;
    }
    default_action : do_add_precordhead;
}

table add_trigger {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        do_add_trigger;
        nop;
    }
    //default_action : do_add_trigger;
}

table add_precord {
    actions {
        do_add_precord;
    }
    default_action : do_add_precord;
}

@pragma stage 9
table store_stat {
    actions {
        do_store_stat;
    }
    default_action : do_store_stat;
}



@pragma stage 9
table get_stat {
    actions {
        do_get_stat;
    }
    default_action : do_get_stat;
}


@pragma stage 9
table store_sip {
    actions {
        do_store_sip;
    }
    default_action : do_store_sip;
}

@pragma stage 9
table get_sip {
    actions {
        do_get_sip;
    }
    default_action : do_get_sip;
}

@pragma stage 3
table store_hash {
    actions {
        do_store_hash;
    }
    default_action : do_store_hash;
}

@pragma stage 3
table get_hash {
    actions {
        do_get_hash;
    }
    default_action : do_get_hash;
}

@pragma stage 4
table store_time_hi {
    actions {
        do_store_time_hi;
    }
    default_action : do_store_time_hi;
}

@pragma stage 4
table get_time_hi {
    actions {
        do_get_time_hi;
    }
    default_action : do_get_time_hi;
}

@pragma stage 4
table store_time_lo {
    actions {
        do_store_time_lo;
    }
    default_action : do_store_time_lo;
}

@pragma stage 4
table get_time_lo {
    actions {
        do_get_time_lo;
    }
    default_action : do_get_time_lo;
}

@pragma stage 7
table get_stat2 {
    actions {
        do_get_stat2;
    }
    default_action : do_get_stat2;
}

@pragma stage 7
table store_stat2 {
    actions {
        do_store_stat2;
    }
    default_action : do_store_stat2;
}

@pragma stage 8
table store_queue_time {
    actions {
        do_store_queue_time;
    }
    default_action : do_store_queue_time;
}

@pragma stage 8
table store_queue_depth {
    actions {
        do_store_queue_depth;
    }
    default_action : do_store_queue_depth;
}

table store_queue_time_1 {
    actions {
        do_store_queue_time_1;
    }
    default_action : do_store_queue_time_1;
}

@pragma stage 8
table get_queue_time {
    actions {
        do_get_queue_time;
    }
    default_action : do_get_queue_time;
}

@pragma stage 8
table get_queue_depth {
    actions {
        do_get_queue_depth;
    }
    default_action : do_get_queue_depth;
}

@pragma stage 4
table get_stat_1 {
    actions {
        do_get_stat;
    }
    default_action : do_get_stat;
}
@pragma stage 3
table get_read_index {
    actions {
        do_get_read_index;
    }
    default_action : do_get_read_index;
}
@pragma stage 2
table get_read_index_1 {
    actions {
        do_get_read_index;
    }
    default_action : do_get_read_index;
}
@pragma stage 2
table get_write_index {
    actions {
        do_get_write_index;
    }
    default_action : do_get_write_index;
}
@pragma stage 2
table get_pread_index {
    actions {
        do_get_pread_index;
    }
    default_action : do_get_pread_index;
}
@pragma stage 2
table get_window_size_1 {
    actions {
        do_get_window_size_1;
    }
    default_action : do_get_window_size_1;
}
@pragma stage 2
table store_checkpt_write_index {
    actions {
        do_store_checkpt_write_index;
    }
    default_action : do_store_checkpt_write_index;
}
@pragma stage 2
table get_checkpt_write_index {
    actions {
        do_get_checkpt_write_index;
    }
    default_action : do_get_checkpt_write_index;
}

@pragma stage 2
table update_window_size {
    actions {
        do_update_window_size;
    }
    default_action : do_update_window_size;
}
@pragma stage 2
table get_window_size {
    actions {
        do_get_window_size;
    }
    default_action : do_get_window_size;
}


table get_window_residue_on_last {
    reads {
        mdata.last_precord : exact;
    }
    actions {
        do_get_window_residue_on_last;
        nop;
    }
    default_action : nop;
}
@pragma stage 5
table get_window_residue {
    actions {
        do_get_window_residue;
    }
    default_action : do_get_window_residue;
}
@pragma stage 5
table store_window_residue {
    actions {
        do_store_window_residue;
    }
    default_action : do_store_window_residue;
}

table act_on_residue {
    reads {
        mdata.window_residue : exact;
    }
    actions {
        do_act_on_residue;
        do_act_on_last_residue;
        no_residue;
    }
    default_action : do_act_on_residue;
}

table dptp_hash {
    reads {
        mdata.hdr_type: exact;
    }
    actions {
        do_dptp_hash;
        nop;
    }
    default_action : nop;
}

table ipv4_hash {
    reads {
        mdata.hdr_type: exact;
    }
    actions {
        do_ipv4_hash;
        nop;
    }
    default_action : nop;
}

table udp_hash {
    reads {
        mdata.hdr_type: exact;
    }
    actions {
        do_udp_hash;
        nop;
    }
    default_action : nop;
}

table classify_switch_precord {
    reads {
        mdata.pkt_type : exact;
        ethernet.srcAddr : exact;
    }
    actions {
        do_classify_switch_precord;
        //nop;
        dont_classify;
    }
    default_action : dont_classify;
}
@pragma stage 2
table calc_queue_time {
    actions {
        do_calc_queue_time;
    }
    default_action : do_calc_queue_time;
}

table calc_queue_time_1 {
    actions {
        do_calc_queue_time;
    }
    default_action : do_calc_queue_time;
}
@pragma stage 8
table count_collect_packets {
    reads {
        mdata.cip : exact;
    }
    actions {
        do_count_collect_packets;
        nop;
    }
    default_action : nop;
}

table trigger_condition_test {
    reads {
        mdata.switch_id : exact;
        //mdata.pstat2 : exact;
    }
    actions {
        do_trigger_condition_test;
        nop;
    }
    default_action : nop;
}


table trigger_condition_pktcount {
    reads {
        mdata.switch_id : exact;
        mdata.phash : exact;
    }
    actions {
        do_trigger_condition_pktcount;
        nop;
    }
    default_action : nop;
}
table check_trigger_hit {
    reads {
        mdata.trigger_hit : exact;
    }
    actions {
        do_make_trigget_packet;
        nop;
    }
    default_action : nop;
}

table reset_precord_entries {
    reads {
        precordhead.entries : exact;
    }
    actions {
        do_reset_precord_entries;
        nop;
    }
    default_action: nop;
}

table calc_precord_entries {
    actions {
        do_calc_precord_entries;
    }
    default_action : do_calc_precord_entries;
}

table get_trigger_id {
    actions {
        do_get_trigger_id;
    }
    default_action : do_get_trigger_id;
}

table store_qdepth {
    actions {
        do_store_qdepth;
    }
    default_action : do_store_qdepth;
}

table calc_avg_qdepth {
    actions {
        do_calc_avg_qdepth;
    }
    default_action : do_calc_avg_qdepth;
}

table calc_max_qdepth {
    actions {
        do_calc_max_qdepth;
    }
    default_action : do_calc_max_qdepth;
}

table calc_min_qdepth {
    actions {
        do_calc_min_qdepth;
    }
    default_action : do_calc_min_qdepth;
}

table store_avg_qdepth {
    actions {
        do_store_avg_qdepth;
    }
    default_action : do_store_avg_qdepth;
}


table check_total_precords {
    reads {
        precordhead.tot_entries : range;
    }
    actions {
        do_check_total_precords;
        nop;
    }
    default_action : nop;
}

table get_last_precord_time {
    actions {
        do_get_last_precord_time;
    }
    default_action : do_get_last_precord_time;
}

table  calc_ipg {
    actions {
        do_calc_ipg;
    }
    default_action : do_calc_ipg;
}

table store_ipg {
    actions {
        do_store_ipg;
    }
    default_action : do_store_ipg;
}

table decr_precord_count {
    reads {
        precordhead.tot_entries : range;
    }
    actions {
        do_decr_precord_count;
    }
}

table assign_pstat {
    //reads {
    //    mdata.switch_id: exact;
    //}
    actions {
    //    calc_pstat_counter;
        do_assign_pstat;
    }
    default_action : do_assign_pstat;
}

table assign_phash {
    reads {
        ig_intr_md.ingress_port : exact;
        mdata.switch_id: exact;
    }
    actions {
        do_calc_phash;
        do_assign_phash;
    }
    default_action : do_assign_phash;
}

table update_packet_hash {
    reads {
        mdata.switch_id : exact;
    }
    actions {
        do_update_packet_hash;
        nop;
    }
    default_action : nop;
}

table post_trigger_counter {
    reads {
        mdata.cip : exact;
    }
    actions {
        do_post_trigger_counter;
    }
}
