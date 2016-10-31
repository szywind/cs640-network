#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

def mk_pkt(etherType, hwsrc, ipsrc, ipdst, hwdst='ff:ff:ff:ff:ff:ff', reply=False):
    '''
    :param etherType: etherType
    :param hwsrc: source MAC address
    :param ipsrc: source IP address
    :param ipdst: target IP address
    :param hwdst: target MAC address
    :param reply: flag to specify arp operation direction
    :return:
    '''
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = etherType

    if etherType == EtherType.ARP:
        arp = Arp()
        if reply:
            arp.operation = ArpOperation.Reply
        else:
            arp.operation = ArpOperation.Request
        arp.senderhwaddr = EthAddr(hwsrc)
        arp.senderprotoaddr = IPAddr(ipsrc)
        arp.targethwaddr = EthAddr(hwdst)
        arp.targetprotoaddr = IPAddr(ipdst)
        return ether + arp

    elif etherType == EtherType.IP:
        ippkt = IPv4()
        ippkt.srcip = IPAddr(ipsrc)
        ippkt.dstip = IPAddr(ipdst)
        ippkt.protocol = IPProtocol.ICMP
        ippkt.ttl = 32

        icmppkt = ICMP()
        if reply:
            icmppkt.icmptype = ICMPType.EchoReply
        else:
            icmppkt.icmptype = ICMPType.EchoRequest
        return ether + ippkt + icmppkt

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.tableIpMac = {}
        self.interfaces = net.interfaces()

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                input_port,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                arp = pkt.get_header(Arp)
                if not arp is None and arp.operation == ArpOperation.Request:
                    # save the source IP/Ethernet MAC pair
                    self.tableIpMac[arp.senderprotoaddr] = arp.senderhwaddr

                    # traverse the interfaces of the router to find the requested target MAC address and reply if hit.
                    for intf in self.interfaces:
                        if arp.targetprotoaddr == intf.ipaddr:
                            # ARP reply
                            replypkt = mk_pkt(EtherType.ARP, intf.ethaddr, arp.targetprotoaddr, arp.senderprotoaddr, arp.senderhwaddr, True)
                            log_debug("ARP reply {} to {}".format(replypkt, input_port))
                            self.net.send_packet(input_port, replypkt)
                            break




def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
