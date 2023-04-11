#
# Simple table setup script for simple_l3.p4
#

clear_all()

# ipv4_host
# p4_pd.ipv4_host_table_add_with_send(
#     p4_pd.ipv4_host_match_spec_t(ipv4Addr_to_i32("192.168.1.1")),
#     p4_pd.send_action_spec_t(1))
#
# p4_pd.ipv4_host_table_add_with_multicast(
#     p4_pd.ipv4_host_match_spec_t(ipv4Addr_to_i32("224.0.0.1")),
#     p4_pd.multicast_action_spec_t(1))
#
# p4_pd.ipv4_host_table_add_with_send(
#     p4_pd.ipv4_host_match_spec_t(ipv4Addr_to_i32("10.10.10.10")),
#     p4_pd.send_action_spec_t(2))

#
# Multicast Engine Programming. We show the names of the parameters here for
# clarity, but they are totally optional and can be omitted for the typing speed
#
try:
    mcg1  = mc.mgrp_create(1)
except:
    print """
clean_all() does not yet support cleaning the PRE programming.
You need to restart the driver before running this script for the second time
"""
    quit()

node1 = mc.node_create(
    rid=0,
    port_map=devports_to_mcbitmap([160]),#,161,162,163,176,177,178,179]),
    lag_map=lags_to_mcbitmap([]))
#print str(devports_to_mcbitmap([1, 3, 8]))
mc.associate_node(mcg1, node1, xid=0, xid_valid=False)

# node2 = mc.node_create(
#     rid=10,
#     port_map=devports_to_mcbitmap([2, 3, 7, 8]),
#     lag_map=lags_to_mcbitmap([]))
# mc.associate_node(mcg1, node2, xid=0, xid_valid=False)

# node3 = mc.node_create(
#     rid=20,
#     port_map=devports_to_mcbitmap([5, 8]),
#     lag_map=lags_to_mcbitmap([]))
# mc.associate_node(mcg1, node3, xid=0, xid_valid=False)

mc.complete_operations()

# Multicast Modifications
# p4_pd.mcast_mods_table_add_with_modify_packet_vlan(
#     p4_pd.mcast_mods_match_spec_t(0, 0, 5, -1),
#     1,  # priority
#     p4_pd.modify_packet_vlan_action_spec_t(
#         action_vlan_id=10,
#         action_dstmac=macAddr_to_string("00:10:11:12:13:14"),
#         action_dstip=ipv4Addr_to_i32("192.168.23.1")))
#
# p4_pd.mcast_mods_table_add_with_modify_packet_no_vlan(
#     p4_pd.mcast_mods_match_spec_t(0, 0, 10, -1),
#     1,  # priority
#     p4_pd.modify_packet_no_vlan_action_spec_t(
#         action_dstmac=macAddr_to_string("00:11:22:33:44:55"),
#         action_dstip=ipv4Addr_to_i32("10.11.12.13")))

conn_mgr.complete_operations()
