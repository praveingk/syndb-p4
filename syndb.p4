/*
 * SyNDB - Synchronized network monitoring & debugging
 */
 
#include "includes/headers.p4"
#include "includes/parser.p4"
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>
#include <tofino/primitives.p4>
#include "tofino/stateful_alu_blackbox.p4"
#include "tofino/lpf_blackbox.p4"
#include "dptp.p4"
#include "syndb-util.p4"


register cp_version {
    width : 32;
    instance_count : MAX_SWITCHES;
}


blackbox stateful_alu cp_version_get {
    reg : cp_version;
    output_value : register_lo;
    output_dst   : mdata.pstat;//mdata.cp_version;
}

register drop_counter {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu get_update_drop_counter {
    reg : drop_counter;
    condition_lo : ig_intr_md_for_tm.ucast_egress_port == 192;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo + 1;
    output_value : alu_lo;
    output_dst : mdata.pstat2;
}

register collect_start_time {
    width : 32;
    instance_count : MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 31 0
blackbox stateful_alu store_collect_start_time {
    reg : collect_start_time;
    update_lo_1_value: ig_intr_md_from_parser_aux.ingress_global_tstamp;
}

register collect_start_time_hi {
    width : 32;
    instance_count : MAX_SWITCHES;
}
@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 47 32
blackbox stateful_alu store_collect_start_time_hi {
    reg : collect_start_time_hi;
    update_lo_1_value: ig_intr_md_from_parser_aux.ingress_global_tstamp;
}
register collect_end_time {
    width : 32;
    instance_count : MAX_SWITCHES;
}

@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 31 0
blackbox stateful_alu store_collect_end_time {
    reg : collect_end_time;
    update_lo_1_value: ig_intr_md_from_parser_aux.ingress_global_tstamp;
}

register collect_end_time_hi {
    width : 32;
    instance_count : MAX_SWITCHES;
}

@pragma stateful_field_slice ig_intr_md_from_parser_aux.ingress_global_tstamp 47 32
blackbox stateful_alu store_collect_end_time_hi {
    reg : collect_end_time_hi;
    update_lo_1_value: ig_intr_md_from_parser_aux.ingress_global_tstamp;
}

register precord_clone {
    width : 32;
    instance_count : MAX_SWITCHES;
}

blackbox stateful_alu check_precord_clone {
    reg : precord_clone;
    condition_lo : register_lo != 0;
    update_lo_1_predicate : condition_lo;
    update_lo_1_value : register_lo - 1;
    update_hi_1_predicate : condition_lo;
    update_hi_1_value : 1;
    output_value : alu_hi;
    output_dst : mdata.clone_precord;
}
action nop() {}

action classify_port_switch(switch_id) {
    modify_field(mdata.switch_id, switch_id);
}

action set_egr(egress_spec) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
}

action set_egr_f(egress_spec, entry_version) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, egress_spec);
    modify_field(mdata.pstat, entry_version);
}

action _drop() {
    drop();
}

action send_to_drop (entry_version) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, 192);
    modify_field(mdata.pstat, entry_version);
}
table mac_forward {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        set_egr;
        nop;
    }
    size:20;
}

table precord_forward {
    reads {
        ethernet.dstAddr : exact;
    }
    actions {
        set_egr;
        nop;
    }
    size:20;
}

table classify_port_logical_switch {
    reads {
        ig_intr_md.ingress_port : exact;
    }
    actions {
        classify_port_switch;
        nop;
    }
}

table forward {
    reads {
        ig_intr_md.ingress_port : exact;
        ethernet.dstAddr : exact;
    }
    actions {
        set_egr_f;
        send_to_drop;
    }
    default_action:send_to_drop;
}

action do_set_ground_clock (switch_id) {
    modify_field(mdata.ground_switch_id, switch_id);
}

action do_get_cp_version () {
    cp_version_get.execute_stateful_alu(mdata.switch_id);
}

action do_update_drop_counter () {
    get_update_drop_counter.execute_stateful_alu(mdata.switch_id);
}

action do_store_collect_start_time () {
    store_collect_start_time.execute_stateful_alu(mdata.switch_id);
}

action do_store_collect_end_time () {
    store_collect_end_time.execute_stateful_alu(mdata.switch_id);
}

action do_store_collect_start_time_hi () {
    store_collect_start_time_hi.execute_stateful_alu(mdata.switch_id);
}

action do_store_collect_end_time_hi () {
    store_collect_end_time_hi.execute_stateful_alu(mdata.switch_id);
}

action do_create_more_precord_packets (session_id) {
    modify_field(mdata.clone_type, PRECORD_CLONE);
    //store_val_test3.execute_stateful_alu(0);
    clone_egress_pkt_to_egress(session_id, clone_pkt_fields);
}

action do_check_precord_clone () {
    check_precord_clone.execute_stateful_alu(mdata.switch_id);
}

action do_remake_precord () {
    modify_field(precordhead.entries, 0);
    modify_field(precordhead.tot_entries, 0);
    modify_field(precordhead.residue, 0);
}
table set_ground_clock{
    reads {
        mdata.switch_id : exact;
    }
    actions {
        do_set_ground_clock;
        nop;
    }
    default_action : nop;
}

table get_cp_version {
    actions{
        do_get_cp_version;
    }
    default_action : do_get_cp_version;
}

table update_drop_counter {
    actions {
        do_update_drop_counter;
    }
    default_action : do_update_drop_counter;
}

table store_collect_start_time {
    actions {
        do_store_collect_start_time;
    }
    default_action : do_store_collect_start_time;
}

table store_collect_end_time {
    actions {
        do_store_collect_end_time;
    }
    default_action : do_store_collect_end_time;
}

table store_collect_start_time_hi {
    actions {
        do_store_collect_start_time_hi;
    }
    default_action : do_store_collect_start_time_hi;
}

table store_collect_end_time_hi {
    actions {
        do_store_collect_end_time_hi;
    }
    default_action : do_store_collect_end_time_hi;
}

table  check_precord_clone {
    actions {
        do_check_precord_clone;
    }
}
table create_more_precord_packets {
    reads {
        mdata.clone_precord : exact;
    }
    actions {
        do_create_more_precord_packets;
    }
}

table remake_precord {
    actions {
        do_remake_precord;
    }
}

// SyNDB 
control ingress {
    // Below logic is for Virtualization of a single switch into a topology using Loop-backs
    apply(acl);
    if (valid(timesync)) {
        apply(classify_logical_switch);
        apply(classify_src_logical_switch);
        apply(flip_address);
    } else {
        apply(classify_port_logical_switch);
    }

    // Store current ingress time for DPTP Request.
    apply(timesyncs2s_store_igTs_hi);
    apply(timesyncs2s_store_igTs_lo);
    // Calculate current DPTP Global Time
    dptp_get_ref();

    apply(dptp_add_elapsed_hi);
    apply(dptp_calc_residue);
    // SyNDB Ingress Logic for checking if its a new trigger has arrived.
    apply(check_trigger);

    apply(classify_switch_precord);

    apply(dptp_compare_residue);
    apply(dptp_compare_igts);
    apply(dptp_add_elapsed_lo);
    apply(dptp_handle_overflow);
    // (dptp_now_hi,dptp_now_lo) is the current global time
    // Handling DPTP request/response
    if (mdata.command == COMMAND_TIMESYNCS2S_RESPONSE) {
        // Got response from Another switch.
        apply(timesyncs2s_store_reference_hi);
        apply(timesyncs2s_store_reference_lo);
        apply(timesyncs2s_store_elapsed_lo);
        apply(timesyncs2s_store_now_macTs_lo);
        apply(timesyncs2s_store_macTs_lo);
        apply(timesyncs2s_store_egTs_lo);
        //apply(timesyncs2s_inform_cp);
        apply(dropit);
    } else if (mdata.command == COMMAND_TIMESYNC_CAPTURE_TX) {
    	if (ig_intr_md.ingress_port != 192) {
            apply(timesyncs2s_store_capture_tx);
            apply(timesyncs2s_inform_cp);
     	}
    }
    // SyNDB Ingress Logic
    // If incoming packet is a RECORDPKT(normal packet), it is recorded.
    // If incoming packet is a precord, its either in collection mode (so, perform collection/forward)
    //    If precord collection is in progress, its recirculated, otherwise, its forwarded to the collector
    // If incoming packet is a trigger packet, start collection.
    if (mdata.pkt_type == RECORDPKT) {
        if (mdata.switch_id != 0) {
            apply(forward);
            apply(get_collect_in_progress);
            //apply(update_cp_version)
        }
    } else if (mdata.pkt_type == PRECORD) {
        if (mdata.dont_record == 1) {
            apply(precord_forward);
        } else {
            apply(reset_precord_entries);
            apply(decr_precord_count);
            apply(handle_precord_collect); // action on the precord packet
        }
    } else if (mdata.pkt_type == TRIGGER) {
        // Act on Trigger Packet
        apply(enable_collect_in_progress);
        apply(store_collect_start_time);
    } else if (mdata.pkt_type == DPTPPKT) {
        apply(mac_forward);
    }
    // Broadcast if its a trigger packet.
    apply(broadcast);
    // Forwarding for all packets based on MAC/IP
    // Copy everything to DPTP packet header
    apply(copy_dptp_packet);
    apply(timesync_inform_cp);
    // Separate queuing for DPTP packets
    apply(qos);

    // Check progress of collection of  precords
    apply(post_trigger_counter);
}

control egress {
    if (pkt_is_not_mirrored) {
        apply(calc_stat_index);
        apply(calc_hash_index);
        apply(timesync_clip_egts);
        // DPTP Logic
        if (valid(timesync)) {
            apply(timesync_capture_ts);
            if (mdata.command == COMMAND_TIMESYNCS2S_REQUEST) {
                // Response packet for Switch to Switch Timesync
                apply(timesyncs2s_gen_response);
            } else if (mdata.command == COMMAND_TIMESYNC_REQUEST) {
                // Response Packet for Switch to Host Timesync
                apply(timesync_gen_response);
                apply(timesync_delta);
                apply(timesync_current_rate);
            } else if (mdata.command == COMMAND_TIMESYNCS2S_GENREQUEST) {
                apply(timesyncs2s_gen_request);
            }
        }
        // SyNDB Egress Logic
        // If Packet is a precord, gets the statistics, and add it to the precord.
        // If packet is a RECORDPKT(normal packet), store statistics, 
        //    Apply test conditions for trigger, and generate trigger if test condition is hit.
        if (mdata.pkt_type == PRECORD) {
            if (mdata.read_precord == 1) {
                    apply(get_pread_index);
                    apply(get_hash);
                    apply(get_time_lo);
                    apply(get_stat2);
                    //apply(get_window_residue);
                    apply(get_queue_time);
                    apply(get_queue_depth);
                    apply(get_stat);
                    apply(get_sip);
                    apply(add_precord);
                    //apply(act_on_residue);
                    apply(store_collect_end_time);
            }
            apply(itest3);
        } else if (mdata.pkt_type == RECORDPKT) {
            if (mdata.stop_record == 0) {
                //apply(assign_pstat);
                apply(assign_phash);
                apply(calc_queue_time);
                apply(get_write_index);
                apply(store_hash);
                apply(itest1);  // A  utilization
                apply(store_time_lo);
                apply(calc_current_utilization); // For
                apply(store_stat2);
                apply(store_queue_time);
                apply(store_queue_depth);
                apply(store_stat);
                apply(store_sip);
                apply(trigger_condition_test); // Checks trigger condtion (queue)
                apply(trigger_condition_pktcount); // Checks trigger condition (packet count)
                // When mdata.trigger_hit is set, create a trigger packet.
                apply(check_trigger_hit);
                apply(update_packet_hash);
            }
        }
    } else {
        // Typical Trigger Packet
        if (mdata.clone_type == TRIGGER_CLONE) {
            apply(get_trigger_id);
            apply(add_trigger);
        } else { 
            apply(itest2);
            apply(remake_precord);
        }
    }
}
