#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

# os.chdir("./Projects/switchyard-master/examples/exercises/router")

class WaitingARP(object):
    def __init__(self, times = 4):
        self.nLeftRetries = times
        self.setTime()
        self.finished = False

    def setTime(self):
        self.ltime = time.time()

    def getTime(self):
        return self.ltime

    def isTimeout(self, curtime):
        return self.getTime() + 1 <= curtime

    def isValid(self, curtime):
        return self.nLeftRetries > 0 or (self.nLeftRetries == 0 and not self.isTimeout(curtime))

    def update(self):
        self.setTime()
        self.nLeftRetries -= 1

    def isFinished(self):
        return self.finished

    def setFinished(self):
        self.finished = True

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
            dir_path = os.path.dirname(os.path.realpath(__file__))
            with open(dir_path + "/forwarding_table.txt", "r") as fl:
                for line in fl:
                    x = line.strip().split()
                    if len(x) == 4:
                        self.forwardTable.append(x)
        except FileNotFoundError:
            pass

        finally:
            ## build FT from router configurations
            for intf in self.interfaces:
                ipaddr = IPv4Address(intf.ipaddr)
                netmask = IPv4Address(intf.netmask)

                prefix = IPv4Address(int(ipaddr) & int(netmask))
                self.forwardTable.append([str(prefix), str(netmask), None, intf.name])

    def lookupFT(self, ipaddr):
        destaddr = IPv4Address(ipaddr)
        ans = None
        maxLength = -1
        for item in self.forwardTable:
            prefixnet = IPv4Network(item[0]+'/'+item[1])

            matches = destaddr in prefixnet
            if matches and prefixnet.prefixlen > maxLength:
                ans = item
                maxLength = prefixnet.prefixlen
        return ans

    def forwarding(self, pkt):
        ippkt = pkt.get_header(IPv4)

        ## lookup forward table
        fwd_info = self.lookupFT(ippkt.dstip)

        if fwd_info is None:
            ## Error handling. 1. If there is no match in the table.
            errMsgPkt = self.mk_icmp_error_pkg(pkt, ICMPType.DestinationUnreachable,
                                                 ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable)
            self.forwarding(errMsgPkt)
            return
        else:
            ## decrease TTL
            ippkt.ttl -= 1
            if ippkt.ttl <= 0:
                ## Error handling. After decrementing an IP packet's TTL value as part of the forwarding process, the TTL becomes zero.
                errMsgPkt = self.mk_icmp_error_pkg(pkt, ICMPType.TimeExceeded,
                                                     ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired)
                self.forwarding(errMsgPkt)
                return

        if fwd_info[2] is None:
            ## next hop is the dst host
            nextHopIP = ippkt.dstip
        else:
            ## next hop is another router
            nextHopIP = IPv4Address(fwd_info[2])   # assert(dstIP is not None)

        nextHopThruPortName = fwd_info[3]
        nextHopThruPort = self.net.interface_by_name(nextHopThruPortName)

        if nextHopIP in self.ipMacTable:
            ## lookup the dst. MAC
            nextHopMAC =  self.ipMacTable[nextHopIP]

            ether = pkt.get_header(Ethernet)
            ether.src = EthAddr(nextHopThruPort.ethaddr)
            ether.dst = EthAddr(nextHopMAC)
            fwdpkt = pkt

            ## for ICMP error messages
            icmppkt = fwdpkt.get_header(ICMP)
            if not icmppkt is None and icmppkt.icmptype in [ICMPType.TimeExceeded, ICMPType.DestinationUnreachable]:
                fwdpkt.get_header(IPv4).srcip = nextHopThruPort.ipaddr

            self.net.send_packet(nextHopThruPortName, fwdpkt)
        else:
            unkownHostIP = [ip_i for (_, _, ip_i, _) in self.queue]
            if nextHopIP not in unkownHostIP:
                ## send ARP request
                arpReqArp = create_ip_arp_request(nextHopThruPort.ethaddr, nextHopThruPort.ipaddr, nextHopIP)
                self.net.send_packet(nextHopThruPortName, arpReqArp)

                ## put this waiting ARP into queue
                self.queue.append((WaitingARP(), nextHopThruPort, nextHopIP, [pkt]))
            else:
                self.queue[unkownHostIP.index(nextHopIP)][-1].append(pkt)



    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                input_port_name, pkt = self.net.recv_packet()
                self.input_port = self.net.interface_by_name(input_port_name)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                return
            except SwitchyException:
                log_debug("Unkown nput port")
                return

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
                                log_debug("ARP reply {} to {}".format(replypkt, self.input_port.name))
                                self.net.send_packet(self.input_port.name, replypkt)
                            except SwitchyException:
                                # If the destination IP address is not assigned to one of the router's interfaces, you should not respond with an ARP reply,
                                pass

                    ## Receive ARP reply packet
                    elif arp.operation == ArpOperation.Reply:

                        # save the IP/Ethernet MAC pair
                        nextHopIP = arp.senderprotoaddr
                        nextHopMAC = arp.senderhwaddr
                        self.ipMacTable[nextHopIP] = nextHopMAC

                        for (arp_i, nextHopThruPort, nextHopIP2, oldfwdpkts) in self.queue:
                            if str(nextHopIP2) == str(nextHopIP):
                                curTime = time.time()
                                if arp_i.isValid(curTime) and not arp_i.isTimeout(curTime):
                                    for fwdpkt in oldfwdpkts:

                                        ## for ICMP error messages
                                        icmppkt = fwdpkt.get_header(ICMP)
                                        if not icmppkt is None and icmppkt.icmptype in [ICMPType.TimeExceeded,
                                                                                        ICMPType.DestinationUnreachable]:
                                            fwdpkt.get_header(IPv4).srcip = nextHopThruPort.ipaddr

                                        ether = fwdpkt.get_header(Ethernet)
                                        ether.src = EthAddr(nextHopThruPort.ethaddr)
                                        ether.dst = EthAddr(nextHopMAC)
                                        self.net.send_packet(nextHopThruPort.name, fwdpkt)
                                        arp_i.setFinished()
                    else:
                        pass
                ## Receive IP packet
                elif pkt.get_header(Ethernet).ethertype == EtherType.IPv4: # assert EtherType.IP == EtherType.IPv4

                    ippkt = pkt.get_header(IPv4)
                    icmppkt = pkt.get_header(ICMP)
                    if not ippkt is None:
                        try:
                            ## 2. If packet is for the router itself
                            port = self.net.interface_by_ipaddr(ippkt.dstip)
                            if (ippkt.protocol == IPProtocol.ICMP) and (not icmppkt is None) and (icmppkt.icmptype == ICMPType.EchoRequest):
                                ## construct an ICMP echo reply and send it back to the original host.
                                etherSender = pkt.get_header(Ethernet)
                                ip = IPv4()
                                ip.srcip = port.ipaddr
                                # assert port.ipaddr == ippkt.dstip
                                ip.dstip = ippkt.srcip
                                ip.protocol = IPProtocol.ICMP
                                ip.ttl = 32

                                icmp = ICMP()
                                icmp.icmptype = ICMPType.EchoReply
                                icmp.icmpdata.data = icmppkt.icmpdata.data  ## icmp.icmpdata = icmppkt.icmpdata # BUG! this will overwrite icmp.icmptype
                                icmp.icmpdata.sequence = icmppkt.icmpdata.sequence
                                icmp.icmpdata.identifier = icmppkt.icmpdata.identifier

                                echoReplyPkt = etherSender + ip + icmp

                                self.forwarding(echoReplyPkt)
                            else:
                                ## Error handling. The only packets destined for the router itself that it knows how to handle are ICMP echo requests.
                                errMsgPkt = self.mk_icmp_error_pkg(pkt, ICMPType.DestinationUnreachable,
                                                                     ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable)
                                self.forwarding(errMsgPkt)
                        except SwitchyException:
                            self.forwarding(pkt)
                else:
                    pass
                #debugger()
            ## maintain the waiting ARP queue
            for (arp_i, nextHopThruPort, nextHopIP, _) in self.queue:
                if arp_i.isFinished():
                    continue
                curTime = time.time()
                if not arp_i.isValid(curTime):
                    continue
                if not arp_i.isTimeout(curTime):
                    continue
                else:
                    ## send ARP request
                    arpReqArp = create_ip_arp_request(nextHopThruPort.ethaddr, nextHopThruPort.ipaddr, nextHopIP)
                    self.net.send_packet(nextHopThruPort.name, arpReqArp)

                    ## update this waiting ARP
                    arp_i.update()

            ## drop ARP pkt after retrying 5 times w/o receiving ARP response
            curTime = time.time()
            # self.queue = [item_j for item_j in self.queue if item_j[0].isValid(curTime)]
            new_queue = []
            for item_j in self.queue:
                if item_j[0].isFinished():
                    continue
                if item_j[0].isValid(curTime):
                    new_queue.append(item_j)
                else:
                    # Error handling. ARP Failure.
                    for cached_pkt in item_j[3]:
                        errMsgPkt = self.mk_icmp_error_pkg(cached_pkt, ICMPType.DestinationUnreachable,
                                                             ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable)
                        self.forwarding(errMsgPkt)
            self.queue = new_queue

    def mk_icmp_error_pkg(self, pkt, icmptype, icmpcode):
        '''
        Error handling. (1) After decrementing an IP packet's TTL value as part of the forwarding process, the TTL becomes zero.
        (2) ARP Failure. (3) Error handling. The only packets destined for the router itself that it knows how to handle are ICMP echo requests.
        (4) If there is no match in the forward table.
        :param pkt: error packet
        :param icmptype: ICMPType.TimeExceeded / DestinationUnreachable / DestinationUnreachable / DestinationUnreachable
        :param icmpcode: ICMPTypeCodeMap[icmp.icmptype].TTLExpired / HostUnreachable / PortUnreachable / NetworkUnreachable
        :param srcip: source IP address when sending back the ICMP error messages
        :return: ICMP error message package
        '''
        ippkt = pkt.get_header(IPv4)
        etherSender = pkt.get_header(Ethernet)

        ether = Ethernet()
        ether.src = self.input_port.ethaddr
        ether.dst = etherSender.src
        ether.ethertype = EtherType.IPv4

        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.srcip = self.input_port.ipaddr  ## default is the incomming port, may be modified to the right port address if necessary.
        ip.dstip = ippkt.srcip
        ip.ttl = 32

        i = pkt.get_header_index(Ethernet)
        del pkt[i]

        icmp = ICMP()
        icmp.icmptype = icmptype
        icmp.icmpcode = icmpcode
        icmp.icmpdata.data = pkt.to_bytes()[:28]
        errMsgPkt = ether + ip + icmp

        return errMsgPkt

def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
