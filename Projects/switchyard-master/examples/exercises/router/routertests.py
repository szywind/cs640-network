'''
Usage  ../../../srpy.py -t -s routertests.py myrouter.py

'''
#!/usr/bin/env python
import sys
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import *

# from enum import Enum
# class PacketType(Enum):
#     IPV4 = 1
#     ARP = 2
#     ICMP = 3

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

def router_tests():
    s = Scenario("router tests")
    s.add_interface('eth0', '10:00:00:00:00:01', '192.168.1.1')
    s.add_interface('eth1', '10:00:00:00:00:02', '192.168.2.1')
    s.add_interface('eth2', '10:00:00:00:00:03', '192.168.3.1')

    test_item_1(s)

    return s


def case_1_1(s):
    # case 1: send non ARP request.
    testPkt = mk_pkt(EtherType.IP, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1', '10:00:00:00:00:01')
    s.expect(PacketInputEvent("eth0", testPkt, display=Ethernet), "An ICMP request should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

    testPkt = mk_pkt(EtherType.IP, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1')
    s.expect(PacketInputEvent("eth0", testPkt, display=Ethernet), "An ICMP request should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

    testPkt = mk_pkt(EtherType.IP, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1', '10:00:00:00:00:02')
    s.expect(PacketInputEvent("eth0", testPkt, display=Ethernet), "An ICMP request should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

    testPkt = mk_pkt(EtherType.ARP, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1', 'ff:ff:ff:ff:ff:ff', True)
    s.expect(PacketInputEvent("eth0", testPkt, display=Ethernet), "An ARP reply should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

def case_1_2(s):
    # case 2: send ARP request for addresses that are assigned to interfaces on the router.
    arpReqPkt = mk_pkt(EtherType.ARP, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1')
    arpRespPkt = mk_pkt(EtherType.ARP, '10:00:00:00:00:01', '192.168.1.1', '192.168.1.100', '30:00:00:00:00:01', True)
    s.expect(PacketInputEvent("eth0", arpReqPkt, display=Arp), "An ARP request for '192.168.1.1' should arrive on router-eth0")
    s.expect(PacketOutputEvent("eth0", arpRespPkt, display=Arp), "The ARP reply should be forwarded out ports router-eth0")

def case_1_3(s):
    # case 3: send ARP request for addresses that are NOT assigned to interfaces on the router.
    arpReqPkt = mk_pkt(EtherType.ARP, '30:00:00:00:00:01', '192.168.1.100', '192.178.1.1')
    s.expect(PacketInputEvent("eth0", arpReqPkt, display=Arp), "An ARP request for '192.178.1.1' should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

def test_item_1(s):
    case_1_1(s)
    case_1_2(s)
    case_1_3(s)






scenario = router_tests()