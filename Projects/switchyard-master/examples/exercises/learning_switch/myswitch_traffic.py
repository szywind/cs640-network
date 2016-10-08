#!/usr/bin/env python3

'''
Ethernet learning switch in Python: Project 1.

Remove an entry from the forwarding table after 10 seconds have elapsed
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

    dstCount = {}
    forwardingTable = {}; # {mac: port}

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

        # update # of times of destination
        if dst_addr in dstCount:
            dstCount[dst_addr] += 1
        else:
            dstCount[dst_addr] = 1

        # log_debug('--------------------------------------------------')
        # log_debug(dstCount)
        # log_debug('--------------------------------------------------')
        # log_debug(forwardingTable)
        # log_debug('--------------------------------------------------')


        if src_addr != broadCastAddr:
            if src_addr not in forwardingTable:
                if len(forwardingTable) < size:
                    forwardingTable[src_addr] = input_port
                else:
                    # check whether to remove one entry
                    min_traffic = float("Inf")
                    min_addr = -1
                    for addr in forwardingTable:
                        log_debug(addr)
                        log_debug(addr in dstCount)
                        if addr not in dstCount:
                            del forwardingTable[addr]
                            forwardingTable[src_addr] = input_port
                            break
                        else:
                            if dstCount[addr] < min_traffic:
                                min_traffic = dstCount[addr]
                                min_addr = addr
                    if src_addr not in dstCount:
                        pass
                    else:
                        # remove the least traffic port
                        if dstCount[src_addr] >= min_traffic:
                            del forwardingTable[min_addr]
                            forwardingTable[src_addr] = input_port
            else:
                forwardingTable[src_addr] = input_port # !!! update the input_port for the address

        if dst_addr in mymacs:
            log_debug ("Packet intended for me")

        else:
            if dst_addr in forwardingTable:
                net.send_packet(forwardingTable[dst_addr], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

    net.shutdown()
