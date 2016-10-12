#!/usr/bin/env python3

'''
Ethernet learning switch in Python: Project 1.

Remove the least recently used (LRU) entry from the forwarding table. For this functionality assume that
your table can only hold 5 entries at a time. If a new entry comes and your table is full, you will remove the entry
that has not been matched with a Ethernet frame destination address for the longest time.
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

import operator

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]

    broadCastAddr = EthAddr("ff:ff:ff:ff:ff:ff")
    size = 5
    id = 1

    forwardingTable = {}; # {mac: [id, port]}

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


        if src_addr != broadCastAddr:
            if src_addr in forwardingTable:
                # just change input source, not update LRU id
                forwardingTable[src_addr][1] = input_port
            else:
                forwardingTable[src_addr] = [id, input_port]
                id += 1
                # remove one entry
                if len(forwardingTable) > size:
                    del forwardingTable[min(forwardingTable.items(), key=operator.itemgetter(1))[0]]


        if dst_addr in mymacs:
            log_debug ("Packet intended for me")
        elif dst_addr in forwardingTable:
            forwardingTable[dst_addr][0] = id
            id += 1
            net.send_packet(forwardingTable[dst_addr][-1], packet)
        else:
            for intf in my_interfaces:
                if input_port != intf.name:
                    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
        log_debug('---------------------------------------')
        # temp = sorted(forwardingTable.items(), key=operator.itemgetter(1), reversed = True)
        log_debug(forwardingTable.values())
    net.shutdown()
