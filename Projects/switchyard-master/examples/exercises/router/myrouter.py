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

# os.chdir("./Projects/switchyard-master/examples/exercises/router")

# def mk_pkt(etherType, hwsrc, ipsrc, ipdst, hwdst='ff:ff:ff:ff:ff:ff', reply=False):
#     '''
#     :param etherType: etherType
#     :param hwsrc: source MAC address
#     :param ipsrc: source IP address
#     :param ipdst: target IP address
#     :param hwdst: target MAC address
#     :param reply: flag to specify arp operation direction
#     :return:
#     '''
#     ether = Ethernet()
#     ether.src = EthAddr(hwsrc)
#     ether.dst = EthAddr(hwdst)
#     ether.ethertype = etherType
#
#     if etherType == EtherType.ARP:
#         arp = Arp()
#         if reply:
#             arp.operation = ArpOperation.Reply
#         else:
#             arp.operation = ArpOperation.Request
#         arp.senderhwaddr = EthAddr(hwsrc)
#         arp.senderprotoaddr = IPAddr(ipsrc)
#         arp.targethwaddr = EthAddr(hwdst)
#         arp.targetprotoaddr = IPAddr(ipdst)
#         return ether + arp
#
#     elif etherType == EtherType.IP:
#         ippkt = IPv4()
#         ippkt.srcip = IPAddr(ipsrc)
#         ippkt.dstip = IPAddr(ipdst)
#         ippkt.protocol = IPProtocol.ICMP
#         ippkt.ttl = 32
#
#         icmppkt = ICMP()
#         if reply:
#             icmppkt.icmptype = ICMPType.EchoReply
#         else:
#             icmppkt.icmptype = ICMPType.EchoRequest
#         return ether + ippkt + icmppkt

# def parseLine(line):
#     ans = (lambda x: x.strip().split(' '))(line)
#     ipaddr = IPv4Address(ans[0])
#     mask = IPv4Address(ans[1])
#     ans[0] = prefix = str(IPv4Address(int(ipaddr) & int(mask)))
#     return ans

class WaitingARP(object):
    def __init__(self, times = 4):
        self.nLeftRetries = times
        self.time = time.time()

    def isTimeout(self, time=time.time()):
        return self.time + 1 <= time

    def isValid(self, time=time.time()):
        return self.nLeftRetries > 0 or (self.nLeftRetries == 0 and not self.isTimeout(time))

    def update(self):
        self.time = time.time()
        self.nLeftRetries -= 1

    def setInvalid(self):
        self.nLeftRetries = -1

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.ipMacTable = {}
        self.interfaces = net.interfaces()

        self.forwardTable = []
        self.setupFT()

        self.queue = []

    def setupFT(self):
        ## build FT from local file
        try:
            with open("./forwarding_table") as fl:
                # for line in fl:
                #     item = line.strip().split(' ')
                #     self.forwardTable[int(item[0]) & int(item[1])] = item[1:]
                # self.tableForward = {[0]: (lambda x: x.strip().split(' '))(line)[1:] for line in fl}

                # self.tableForward.extend(parseLine(line) for line in fl)
                self.tableForward.extend((lambda x: x.strip().split(' '))(line) for line in fl)

        except FileNotFoundError:
            pass

        ## build FT from router configurations
        for intf in self.interfaces:
            ipaddr = IPv4Address(intf.ipaddr)
            netmask = IPv4Address(intf.netmask)

            prefix = IPv4Address(int(ipaddr) & int(netmask))
            self.forwardTable.append([str(prefix), str(netmask), None, intf.name])

            # assert int(ipaddr) == int(ipaddr) & int(netmask)
            # self.forwardTable.append([str(ipaddr), str(netmask), None, intf.name])

    def lookupFT(self, ipaddr):
        destaddr = IPv4Address(ipaddr)
        ans = None
        maxLength = -1
        for item in self.forwardTable:
            prefix = IPv4Address(item[0])
            matches = (int(prefix) & int(destaddr)) == int(prefix)

            netaddr = IPv4Network(item[0]+'/'+item[1])
            if matches and netaddr.prefixlen > maxLength:
                ans = item
        return ans

    def forwarding(self, pkt):
        ippkt = pkt.get_header(IPv4)

        if not ippkt is None:

            try:
                ## 2. If packet is for the router itself (i.e., destination address is an address of one of the router's interfaces), also drop/ignore the packet.
                self.net.interface_by_ipaddr(ippkt.dstip)
                return
            except SwitchyException:
                ## decrease TTL
                ippkt.ttl -= 1

                ## lookup forward table
                fwd_info = self.lookupFT(ippkt.dstip)
                if fwd_info is None:
                    ## 1. If there is no match in the table, just drop the packet.
                    return

                if fwd_info[2] is None:
                    ## next hop is the dst host
                    nextHopIP = ippkt.dstip
                else:
                    ## next hop is another router
                    nextHopIP = fwd_info[2]   # assert(dstIP is not None)

                nextHopThruPortName = fwd_info[3]
                nextHopThruPort = self.net.interface_by_name(nextHopThruPortName)

                if nextHopIP in self.ipMacTable:
                    ## lookup the dst. MAC
                    nextHopMAC =  self.ipMacTable[nextHopIP]

                    ## unencapsulate Ethernet header
                    # ether_index = pkt.get_header_index(Ethernet)
                    # ether_type = pkt[ether_index].ethertype
                    # del pkt[ether_index]

                    # ether = Ethernet()
                    ether = pkt.get_header(Ethernet)
                    ether.src = EthAddr(nextHopThruPort.ethaddr)
                    ether.dst = EthAddr(nextHopMAC)
                    # ether.ethertype = ether_type

                    # fwdpkt = ether + pkt
                    fwdpkt = pkt
                    self.net.send_packet(nextHopThruPortName, fwdpkt)
                else:
                    ## send ARP request
                    arpReqArp = create_ip_arp_request(nextHopThruPort.ethaddr, nextHopThruPort.ipaddr, nextHopIP)
                    self.net.send_packet(nextHopThruPortName, arpReqArp)

                    ## put this waiting ARP into queue
                    self.queue.append((WaitingARP(), nextHopThruPort, nextHopIP, pkt))




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
                if not arp is None:
                    ## Receive ARP request packet
                    if arp.operation == ArpOperation.Request:
                        ## save the source IP/Ethernet MAC pair
                        self.ipMacTable[arp.senderprotoaddr] = arp.senderhwaddr

                        if not arp.targetprotoaddr is None:
                            ##  determine whether the targetprotoaddr field (IP address destination) in the ARP header is an IP address assigned to one of the interfaces on your router
                            try:
                                port = self.net.interface_by_ipaddr(arp.targetprotoaddr)
                                ## ARP reply
                                replypkt = create_ip_arp_reply(port.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                                #replypkt = mk_pkt(EtherType.ARP, port.ethaddr, arp.targetprotoaddr, arp.senderprotoaddr, arp.senderhwaddr, True)
                                log_debug("ARP reply {} to {}".format(replypkt, input_port))
                                self.net.send_packet(input_port, replypkt)
                            except SwitchyException:
                                # If the destination IP address is not assigned to one of the router's interfaces, you should not respond with an ARP reply,
                                pass

                    ## Receive ARP reply packet
                    else:
                        assert arp.operation == ArpOperation.Reply

                        # save the IP/Ethernet MAC pair
                        nextHopIP = arp.senderprotoaddr
                        nextHopMAC = arp.senderhwaddr
                        self.ipMacTable[nextHopIP] = nextHopMAC

                        for (arp_i, nextHopThruPort, nextHopIP2, oldfwdpkt) in self.queue:
                            if nextHopIP2 == nextHopIP:
                                if arp_i.isValid() and not arp_i.isTimeout():
                                    ## unencapsulate Ethernet header
                                    # ether_index = oldfwdpkt.get_header_index(Ethernet)
                                    # ether_type = oldfwdpkt[ether_index].ethertype
                                    # del oldfwdpkt[ether_index]

                                    ether = oldfwdpkt.get_header(Ethernet)
                                    # ether = Ethernet()
                                    ether.src = EthAddr(nextHopThruPort.ethaddr)
                                    ether.dst = EthAddr(nextHopMAC)
                                    # ether.ethertype = ether_type

                                    # fwdpkt = ether + oldfwdpkt
                                    fwdpkt = oldfwdpkt
                                    self.net.send_packet(nextHopThruPort.name, fwdpkt)
                                    arp_i.setInvalid()

                ## Receive IP packet
                else:
                    self.forwarding(pkt)

            ## maintain the waiting ARP queue
            for (arp_i, nextHopThruPort, nextHopIP, _) in self.queue:
                if not arp_i.isValid():
                    continue
                if not arp_i.isTimeout():
                    continue
                else:
                    ## send ARP request
                    arpReqArp = create_ip_arp_request(nextHopThruPort.ethaddr, nextHopThruPort.ipaddr, nextHopIP)
                    self.net.send_packet(nextHopThruPort.name, arpReqArp)

                    ## update this waiting ARP
                    arp_i.update()

            ## drop ARP pkt after retrying 5 times w/o receiving ARP response
            self.queue = [item_j for item_j in self.queue if item_j[0].isValid()]

def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
