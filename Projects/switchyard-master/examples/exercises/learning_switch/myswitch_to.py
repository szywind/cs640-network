#!/usr/bin/env python3

'''
Ethernet learning switch in Python: Project 1.

Remove an entry from the forwarding table after 10 seconds have elapsed
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

import time

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    broadCastAddr = EthAddr("ff:ff:ff:ff:ff:ff")
    timeRefresh = 10

    forwardingTable = {}; # {mac: [port, time]}

    while True:
        try:
            input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug("In {} received packet {} on {}".format(net.name, packet, input_port))

        src_addr = packet[0].src
        dst_addr = packet[0].dst

        recv_time = time.time()

        if src_addr != broadCastAddr:
            forwardingTable[src_addr] = [input_port, recv_time]

        if dst_addr in mymacs:
            log_debug ("Packet intended for me")
        elif dst_addr in forwardingTable:
            if recv_time - forwardingTable[dst_addr][1] < timeRefresh:
                net.send_packet(forwardingTable[dst_addr][0], packet)
            else:
                del forwardingTable[dst_addr]
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)

    net.shutdown()
