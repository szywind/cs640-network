'''
Usage  ../../../srpy.py -t -s routertests.py myrouter.py

'''
#!/usr/bin/env python
import sys
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import *
import copy

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

    elif etherType == EtherType.IPv4:
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

def mk_fwd_pkt(pkt, hwsrc, hwdst):
    '''
    make forwarding packet from input packet
    :param pkt: old packet
    :param hwsrc: new source MAC address
    :param hwdst: new destination MAC address
    :return: new packet
    '''
    fwdPkt = copy.deepcopy(pkt) # should use deep copy to ensure fwdPkt and testPkt are not identical and feed them to the scenario
    ether = fwdPkt.get_header(Ethernet)
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)

    ippkt = fwdPkt.get_header(IPv4)
    ippkt.ttl -= 1

    return fwdPkt


def mk_icmp_error_pkg(pkt, icmptype, icmpcode, hwsrc, hwdst, ipsrc):
    '''
    Error handling. (1) After decrementing an IP packet's TTL value as part of the forwarding process, the TTL becomes zero.
    (2) ARP Failure. (3) Error handling. The only packets destined for the router itself that it knows how to handle are ICMP echo requests.
    (4) If there is no match in the forward table.
    :param pkt: error packet
    :param icmptype: ICMPType.TimeExceeded / DestinationUnreachable / DestinationUnreachable / DestinationUnreachable
    :param icmpcode: ICMPTypeCodeMap[icmp.icmptype].TTLExpired / HostUnreachable / PortUnreachable / NetworkUnreachable
    :return: ICMP error message package
    '''
    temp = copy.deepcopy(pkt)
    ippkt = temp.get_header(IPv4)
    i = temp.get_header_index(Ethernet)
    del temp[i]

    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IPv4

    ip = IPv4()
    ip.protocol = IPProtocol.ICMP
    ip.srcip = IPv4Address(ipsrc)
    ip.dstip = ippkt.srcip
    ip.ttl = 32

    icmp = ICMP()
    icmp.icmptype = icmptype
    icmp.icmpcode = icmpcode
    icmp.icmpdata.data = temp.to_bytes()[:28]
    errMsgPkt = ether + ip + icmp

    return errMsgPkt


def router_tests():
    s = Scenario("router tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '100.1.220.1', '255.255.128.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '100.1.220.2', '255.255.192.0')
    # s.add_interface('eth3', '10:00:00:00:00:04', '123.15.103.12', '255.255.255.128')

    test_item_1(s)
    test_item_2_3(s)
    test_item_4_5(s)

    return s


def case_1(s):
    # case 1: send non ARP request.
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1', '10:00:00:00:00:01')
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet), "An ICMP request should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1')
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet), "An ICMP request should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1', '10:00:00:00:00:02')
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet), "An ICMP request should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

    testPkt = mk_pkt(EtherType.ARP, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1', 'ff:ff:ff:ff:ff:ff', True)
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet), "An ARP reply should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")

def case_2(s):
    # case 2: send ARP request for addresses that are assigned to interfaces on the router.
    arpReqPkt = mk_pkt(EtherType.ARP, '30:00:00:00:00:01', '192.168.1.100', '192.168.1.1')
    arpRespPkt = mk_pkt(EtherType.ARP, '10:00:00:00:00:01', '192.168.1.1', '192.168.1.100', '30:00:00:00:00:01', True)
    s.expect(PacketInputEvent("router-eth0", arpReqPkt, display=Arp), "An ARP request for '192.168.1.1' should arrive on router-eth0")
    s.expect(PacketOutputEvent("router-eth0", arpRespPkt, display=Arp), "The ARP reply should be forwarded out ports router-eth0")

def case_3(s):
    # case 3: send ARP request for addresses that are NOT assigned to interfaces on the router.
    arpReqPkt = mk_pkt(EtherType.ARP, '30:00:00:00:00:01', '192.168.1.100', '192.178.1.1')
    s.expect(PacketInputEvent("router-eth0", arpReqPkt, display=Arp), "An ARP request for '192.178.1.1' should arrive on router-eth0")
    s.expect(PacketInputTimeoutEvent(1.0), "No ARP reply")



## -----------------------------------------------------------------------------------------------------------
def case_4(s):
    # case 4: send packet to the router itself
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '100.1.220.2')
    s.expect(PacketInputEvent("router-eth1", testPkt, display=Ethernet), "IP packet to '100.1.192.2' should arrive on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.0), "The packet should be dropped")

def case_5(s):
    # case 5: if there is no match in the table, just drop the packet.
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '111.1.220.2')
    s.expect(PacketInputEvent("router-eth1", testPkt, display=Ethernet), "IP packet to '111.1.192.2' should arrive on router-eth1")
    s.expect(PacketInputTimeoutEvent(1.0), "The packet should be dropped")

def case_6(s):
    # case 6: forward to direct host
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '100.1.230.66', '30:00:00:00:06:06')
    s.expect(PacketInputEvent("router-eth1", testPkt, display=Ethernet), "IP packet to '100.1.230.66' should arrive on router-eth1")

    arpReqPkt = mk_pkt(EtherType.ARP, '10:00:00:00:00:03', '100.1.220.2', '100.1.230.66')
    s.expect(PacketOutputEvent("router-eth2", arpReqPkt, display=Ethernet), "ARP request from router-eth2")

    arpRespPkt = mk_pkt(EtherType.ARP, '30:00:00:00:05:01', '100.1.230.66', '100.1.220.2', '10:00:00:00:00:03', True)
    s.expect(PacketInputEvent("router-eth2", arpRespPkt, display=Ethernet), "ARP respond to router-eth2")

    fwdPkt = mk_fwd_pkt(testPkt, '10:00:00:00:00:03', '30:00:00:00:05:01')
    s.expect(PacketOutputEvent("router-eth2", fwdPkt, display=Ethernet), "Forward IP packet to '100.1.230.66'")

def case_7(s):
    # case 7: forward to indirect host through other routers with ARP if necessary
    # and if the dst. MAC is in the IP/MAC table, it will not send ARP again.
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '172.16.128.40', '66:66:66:66:66:66')
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet), "IP packet to '172.16.128.40' should arrive on router-eth0")

    arpReqPkt = mk_pkt(EtherType.ARP, '10:00:00:00:00:02', '100.1.220.1', '10.10.0.254') # '10.10.0.254' is next hop
    s.expect(PacketOutputEvent("router-eth1", arpReqPkt, display=Ethernet), "ARP request from router-eth1")

    arpRespPkt = mk_pkt(EtherType.ARP, '30:00:00:00:06:01', '10.10.0.254', '100.1.220.1', '10:00:00:00:00:02', True)
    s.expect(PacketInputEvent("router-eth1", arpRespPkt, display=Ethernet), "ARP respond to router-eth1")

    fwdPkt = mk_fwd_pkt(testPkt, '10:00:00:00:00:02', '30:00:00:00:06:01')
    s.expect(PacketOutputEvent("router-eth1", fwdPkt, display=IPv4), "Forward IP packet to '10.10.0.254'")

    # ippkt = testPkt.get_header(IPv4)
    # assert (ippkt.ttl == 32)
    # ippkt = fwdPkt.get_header(IPv4)
    # assert (ippkt.ttl == 31)

    s.expect(PacketInputEvent("router-eth1", testPkt, display=Ethernet), "IP packet to '172.16.128.40' should arrive on router-eth1")
    fwdPkt = mk_fwd_pkt(testPkt, '10:00:00:00:00:02', '30:00:00:00:06:01')
    s.expect(PacketOutputEvent("router-eth1", fwdPkt, display=IPv4), "Forward IP packet to '10.10.0.254'")

def case_8(s):
    # case 8: resend ARP request after 1.0s timeout
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '192.168.1.100', '172.16.0.0', '88:88:88:88:88:88')
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet), "IP packet to '172.16.0.0' should arrive on router-eth0")

    for i in range(3):
        arpReqPkt = mk_pkt(EtherType.ARP, '10:00:00:00:00:01', '192.168.1.1', '192.168.1.2')  # '192.168.1.2' is next hop
        s.expect(PacketOutputEvent("router-eth0", arpReqPkt, display=Ethernet), "ARP request from router-eth0")

        s.expect(PacketInputTimeoutEvent(1.0), "Wait for 1.0 second")

    s.expect(PacketInputTimeoutEvent(1.0), "The waiting ARP should be dropped.")

## -----------------------------------------------------------------------------------------------------------
def case_9(s):
    # case 9: icmp reply
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:00:01', '100.1.230.55', '100.1.220.1', '10:00:00:00:00:02')
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet),
             "An ICMP request to '100.1.220.1'(interface of the router) arrive on router-eth0 and ICMP reply should be triggered.")

    arpReqPkt = mk_pkt(EtherType.ARP, '10:00:00:00:00:03', '100.1.220.2', '100.1.230.55')
    s.expect(PacketOutputEvent("router-eth2", arpReqPkt, display=Ethernet), "ARP request for '100.1.230.55' from router-eth2")

    arpRespPkt = mk_pkt(EtherType.ARP, '30:00:00:00:05:01', '100.1.230.55', '100.1.220.2', '10:00:00:00:00:03', True)
    s.expect(PacketInputEvent("router-eth2", arpRespPkt, display=Ethernet), "ARP respond to router-eth2")

    icmpReplyPkt = mk_pkt(EtherType.IPv4, '10:00:00:00:00:03', '100.1.220.1', '100.1.230.55', '30:00:00:00:05:01', True)
    icmpReplyPkt.get_header(IPv4).ttl -= 1
    s.expect(PacketOutputEvent("router-eth2", icmpReplyPkt, display=Ethernet), "ICMP respond to '100.1.230.55' via router-eth2")

def case_10(s):
    # case 10-1: error handling for TTL timeout
    testPkt = mk_pkt(EtherType.IPv4, '30:00:00:00:10:01', '100.1.230.56', '100.1.220.3', '99:99:99:99:99:99')
    testPkt.get_header(IPv4).ttl = 1
    s.expect(PacketInputEvent("router-eth0", testPkt, display=Ethernet), "An ICMP request to '100.1.220.3' should arrive on router-eth0.")

    arpReqPkt = mk_pkt(EtherType.ARP, '10:00:00:00:00:03', '100.1.220.2', '100.1.230.56')
    s.expect(PacketOutputEvent("router-eth2", arpReqPkt, display=Ethernet),
             "ARP request for '100.1.230.56' from router-eth2")

    arpRespPkt = mk_pkt(EtherType.ARP, '30:00:00:00:10:01', '100.1.230.56', '100.1.220.2', '10:00:00:00:00:03', True)
    s.expect(PacketInputEvent("router-eth2", arpRespPkt, display=Ethernet), "ARP respond to router-eth2")


    temp = mk_pkt(EtherType.IPv4, '30:00:00:00:10:01', '100.1.230.56', '100.1.220.3', '99:99:99:99:99:99')
    temp.get_header(IPv4).ttl = 0
    errMsgPkt = mk_icmp_error_pkg(temp, ICMPType.TimeExceeded, ICMPTypeCodeMap[ICMPType.TimeExceeded].TTLExpired, '10:00:00:00:00:03', '30:00:00:00:10:01', '100.1.220.2')
    errMsgPkt.get_header(IPv4).ttl -= 1
    s.expect(PacketOutputEvent("router-eth2", errMsgPkt, display=ICMP), "ICMP error reply for TTL timeout via router-eth2")

    # case 10-2: error handling for network unreachable (missing destination in forwarding table)
    testPkt2 = mk_pkt(EtherType.IPv4, '30:00:00:00:10:01', '100.1.230.56', '9.9.9.9', '99:99:99:99:99:99')
    s.expect(PacketInputEvent("router-eth0", testPkt2, display=Ethernet), "An ICMP request to '9.9.9.9' should arrive on router-eth0.")

    errMsgPkt2 = mk_icmp_error_pkg(testPkt2, ICMPType.DestinationUnreachable, ICMPTypeCodeMap[ICMPType.DestinationUnreachable].NetworkUnreachable, '10:00:00:00:00:03', '30:00:00:00:10:01', '100.1.220.2')
    errMsgPkt2.get_header(IPv4).ttl -= 1
    s.expect(PacketOutputEvent("router-eth2", errMsgPkt2, display=ICMP), "ICMP error reply for network unreachable via router-eth2")

    # case 10-3: error handling for port unreachable
    testPkt3 = mk_pkt(EtherType.IPv4, '30:00:00:00:10:01', '100.1.230.56', '100.1.220.2', '10:00:00:00:00:03', True)

    s.expect(PacketInputEvent("router-eth0", testPkt3, display=Ethernet), "An ICMP reply to '100.1.220.2' should arrive on router-eth0.")

    errMsgPkt3 = mk_icmp_error_pkg(testPkt3, ICMPType.DestinationUnreachable, ICMPTypeCodeMap[ICMPType.DestinationUnreachable].PortUnreachable, '10:00:00:00:00:03', '30:00:00:00:10:01', '100.1.220.2')
    errMsgPkt3.get_header(IPv4).ttl -= 1
    s.expect(PacketOutputEvent("router-eth2", errMsgPkt3, display=ICMP), "ICMP error reply for port unreachable via router-eth2")


    # case 10-4: error handling for ARP failure
    testPkt4 = mk_pkt(EtherType.IPv4, '30:00:00:00:10:01', '100.1.230.56', '100.1.230.57', '99:99:99:99:99:99')
    s.expect(PacketInputEvent("router-eth0", testPkt4, display=Ethernet), "IP packet to '100.1.230.57' should arrive on router-eth0")

    for i in range(5):
        arpReqPkt4 = mk_pkt(EtherType.ARP, '10:00:00:00:00:03', '100.1.220.2', '100.1.230.57')
        s.expect(PacketOutputEvent("router-eth2", arpReqPkt4, display=Ethernet), "ARP request from router-eth2")
        s.expect(PacketInputTimeoutEvent(1.0), "Wait for 1.0 second")

    temp = mk_pkt(EtherType.IPv4, '30:00:00:00:10:01', '100.1.230.56', '100.1.230.57', '99:99:99:99:99:99')
    temp.get_header(IPv4).ttl = 31
    errMsgPkt4 = mk_icmp_error_pkg(temp, ICMPType.DestinationUnreachable, ICMPTypeCodeMap[ICMPType.DestinationUnreachable].HostUnreachable, '10:00:00:00:00:03', '30:00:00:00:10:01', '100.1.220.2')
    errMsgPkt4.get_header(IPv4).ttl -= 1
    s.expect(PacketOutputEvent("router-eth2", errMsgPkt4, display=ICMP), "ICMP error reply for ARP failure via router-eth2")


def test_item_1(s):
    # case_1(s)
    case_2(s)
    case_3(s)

def test_item_2_3(s):
    # case_4(s)
    # case_5(s)
    case_6(s)
    case_7(s)
    # case_8(s)

def test_item_4_5(s):
    case_9(s)
    case_10(s)


scenario = router_tests()