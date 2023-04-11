header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header ethernet_t ethernet;

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header ipv4_t ipv4;


field_list ipv4_field_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_chksum_calc {
    input {
        ipv4_field_list;
    }
    algorithm : csum16;
    output_width: 16;
}

calculated_field ipv4.hdrChecksum {
    update ipv4_chksum_calc;
}

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 3;
        ecn : 3;
        ctrl : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}
header tcp_t tcp;

header_type udp_t { // 8 bytes
    fields {
        srcPort : 16;
        dstPort : 16;
        // hdr_length : 16;
        // checksum : 16;
        checksum : 32;
    }
}

header udp_t udp;

header_type timesync_t {
    fields {
        magic : 16;
        command : 8;
        reference_ts_hi : 32;
        reference_ts_lo : 32;
        era_ts_hi : 32;
        current_rate : 32;
        igmacts : 48;
        igts : 48;
        egts : 48;
        capturets : 48;
    }
}

header timesync_t timesync;

header_type trigger_t {
    fields {
        trigger_id : 32;
        trigger_hit_time : 32; // ts_lo
        //trigger_origin : 8;  // switch_id
    }
}
header trigger_t trigger;

header_type coal_t {
    fields {
        coal_test : 32;
    }
}
header coal_t coal;

header_type precordhead_t {
    fields {
        update_time : 48;
        residue : 8;
        tot_entries : 8;
        //roll    : 8;
        entries : 8;
    }
}
header precordhead_t precordhead;

//@pragma not_parsed
header_type precord_t {
    fields {
        phash : 32;
        ptime_in : 32;
        pqueue   : 32;
        pstat : 32;
        pstat2 : 32;
        pqueuedepth : 32;
        psip : 32;
    }
}
#define MAX_PRECORDS 16
#define MAX_PRECORDS_PARSED 2

//@pragma not_parsed
header precord_t precord[MAX_PRECORDS_PARSED];





header_type metadata_t {
    fields {
        command : 8;
        reference_ts_hi : 32;
        reference_ts_lo : 32;
        era_ts_hi : 32;
        era_ts_lo : 32;
        global_ts_hi : 32;
        global_ts_lo : 32;
        result_ts_hi : 32;
        result_ts_lo : 32;
        global_ts : 48;
        mac_timestamp_clipped : 32;
        ingress_timestamp_clipped_hi : 32;
        ingress_timestamp_clipped : 32;
        egress_timestamp_clipped : 32;
        reqdelay : 32;
        capture_tx : 32;
        switch_id : 32;
        src_switch_id : 32;
        ground_switch_id : 32;
        current_utilization : 32;
        link : 32;
        lpf_test : 32;
        port_switch_id : 32;
        pipe : 32;
        dptp_now_hi : 32;
        dptp_now_lo : 32;
        dptp_overflow_hi : 32;
        dptp_overflow_lo : 32;
        dptp_residue : 32;
        dptp_compare_residue : 32;
        dptp_overflow : 1;
        dptp_overflow_compare : 32;
        hack_for_dup_packet: 8;
        new_ingress_count : 32;
        packet_hash : 32;
        max_snap_pkts : 32;
        max_precords : 8;
        pstat : 32;
        phash : 32;
        pqueue : 32;
        ptime_hi : 32;
        ptime_lo : 32;
        clone_pkt : 1;
        read_index : 32;
        write_index : 32;
        window_residue : 32;
        checkpt_write_index : 32;
        window_not_empty : 1;
        write_precord : 1;
        precordhead_duration : 32;
        pde : 8; //precordhead_duration_expiry
        trigger_act : 1;
        trigger_act_egress : 1;
        pkt_type : 8;
        hdr_type : 8;
        cip : 8; //collect_in_progress
        collect_pkts_done : 1;
        collect_done : 2;
        snap_pkts : 32;
        test1 : 8;
        last_precord : 1;
        window_size : 32;
        start_index : 32;
        end_index : 32;
        test : 16;
        collect_packets :32;
        trigger_hit : 1;
        precord_entries : 8;
        trigger_id : 32;
        pkt : 8;
        precord_entries_avail : 1;
        avg_qdepth : 32;
        precord_duration : 32;
        last_precord_time : 32;
        ipg : 32 (signed);
        read_precord : 1;
        dont_record : 1;
        previous_trigger : 8;
        hash_start : 32;
        hash_end : 32;
        cp_version : 32;
        pstat2 : 32;
        stop_record : 1;
        lpf_index : 32;
        clone_precord : 1;
        clone_type : 8;
        psip : 32;
        pqueuedepth : 32;
    }
}

metadata metadata_t mdata;


field_list hash_fields {
    ethernet.srcAddr;
}

field_list_calculation src_hash {
    input { hash_fields; }
    algorithm: random;
    output_width: 16;
}
