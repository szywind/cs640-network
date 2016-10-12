#!/usr/bin/env python3

'''
Ethernet learning switch in Python: Project 1.

Remove the entry that has the least traffic volume. For this functionality assume that your table can only hold
5 entries at a time. Traffic volume for an entry is the number of frames that the switch received where
Destination MAC address == MAC address of entry.
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

    forwardingTable = {}; # {mac: [traffic, port]}

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
                # !!! update the port for the src_address if necessary
                forwardingTable[src_addr][1] = input_port
            else:
                if len(forwardingTable) < size:
                    forwardingTable[src_addr] = [0, input_port]
                else:
                    # remove one entry
                    del forwardingTable[min(forwardingTable.items(), key=operator.itemgetter(1))[0]]
                    forwardingTable[src_addr] = [0, input_port]

        # update traffic volume
        if dst_addr in forwardingTable:
            forwardingTable[dst_addr][0] += 1

        if dst_addr in mymacs:
            log_debug ("Packet intended for me")

        else:
            if dst_addr in forwardingTable:
                net.send_packet(forwardingTable[dst_addr][-1], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

    net.shutdown()
