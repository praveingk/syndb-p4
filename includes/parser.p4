#define ETHERTYPE_COAL 0x1234
#define ETHERTYPE_SNAP 0x1235
#define ETHERTYPE_TRIG 0x1236
#define ETHERTYPE_COLL 0x1237

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_TIMESYNC 0x88F7

#define PRECORD 0x1
#define RECORDPKT 0x11
#define TRIGGER 0x12
#define DPTPPKT 0x13

#define DPTP 0x1
#define IPV4 0x2
#define UDP  0x3
#define TCP  0x4

#define _parser_counter_ ig_prsr_ctrl.parser_counter

parser start {
	return select(current(96,16)){
		ETHERTYPE_TRIG : parse_trigger;
		default: parse_ethernet;
	}
}

parser parse_trigger {
	extract(ethernet);
	extract(trigger);
    set_metadata(mdata.pkt_type, TRIGGER);
    return ingress;
}

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        /** Fill Whatever ***/
		ETHERTYPE_IPV4 : parse_ipv4;
	    ETHERTYPE_TIMESYNC : parse_timesync;
		//ETHERTYPE_TRIG : parse_trigger;
       	ETHERTYPE_COAL : parse_coal;
       	ETHERTYPE_SNAP : parse_precordhead_entry;
       	ETHERTYPE_COLL : parse_precordhead_entry;
        default: ingress;
    }
}

parser parse_timesync {
	set_metadata(mdata.hdr_type, DPTP);
	set_metadata(mdata.pkt_type, DPTPPKT);
    extract(timesync);
    set_metadata(mdata.command, latest.command);
    set_metadata(mdata.reference_ts_hi, latest.reference_ts_hi);
    set_metadata(mdata.reference_ts_lo, latest.reference_ts_lo);
    set_metadata(mdata.result_ts_hi, 0);
    set_metadata(mdata.result_ts_lo, 0);
    return ingress;
}

parser parse_ipv4 {
    extract(ipv4);
	set_metadata(mdata.pkt, 1);
	return select(ipv4.protocol) {
	    6 : parse_tcp;
       17 : parse_udp;
	   default : parse_just_ipv4;
	}
}
parser parse_just_ipv4 {
	set_metadata(mdata.hdr_type, IPV4);

	// set_metadata(mdata.pkt_type, RECORDPKT);
	return ingress;
}
parser parse_tcp {
    set_metadata(mdata.pkt_type, RECORDPKT);
	set_metadata(mdata.hdr_type, TCP);
    extract(tcp);
    return ingress;
}

parser parse_udp {
    set_metadata(mdata.pkt_type, RECORDPKT);
	set_metadata(mdata.hdr_type, UDP);
    extract(udp);
    return ingress;
}

parser parse_coal {
    set_metadata(mdata.pkt_type, RECORDPKT);
    extract(coal);
    return ingress;
}


parser parse_precordhead_entry {
	set_metadata(mdata.pkt_type, PRECORD);
    extract(precordhead);
	set_metadata(_parser_counter_, precordhead.entries);
	return parse_precordhead;
}

@pragma terminate_parsing ingress
parser parse_precordhead {
    return select(_parser_counter_) {
        0x0     : ingress;
        default : parse_precord;
    }
}

parser parse_precord {
    extract(precord[next]);
    set_metadata(_parser_counter_, _parser_counter_ - 1);
    return select(_parser_counter_) {
        0x0     : ingress;
        default : parse_precord;
    }
}
//parser parse_precordhead {
//    set_metadata(mdata.pkt_type, PRECORD);
//    extract(precordhead);
//    return parse_precord;
//}

//@pragma not_parsed
//@pragma terminate_parsing
//parser parse_precord {
//	extract(precord[0]);
//	return parse_extra_precord;
//}

//@pragma terminate_parsing
//parser parse_extra_precord {
//extract(precord[1]);
//	return ingress;
//}
