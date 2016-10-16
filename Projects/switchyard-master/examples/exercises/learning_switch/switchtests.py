#!/usr/bin/env python
'''
Usage  ../../../srpy.py -t -s switchtests.py myswitch_to.py

'''
import sys
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import *

import time

def mk_pkt(hwsrc, hwdst):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP

    ippkt = IPv4()
    # ippkt.srcip = IPAddr(ipsrc)
    # ippkt.dstip = IPAddr(ipdst)
    # ippkt.protocol = IPProtocol.ICMP
    # ippkt.ttl = 32

    icmppkt = ICMP()
    # if reply:
    #     icmppkt.icmptype = ICMPType.EchoReply
    # else:
    #     icmppkt.icmptype = ICMPType.EchoRequest

    return ether + ippkt + icmppkt

def switch_tests():
    s = Scenario("switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    s.add_interface('eth3', '10:00:00:00:00:04')
    s.add_interface('eth4', '10:00:00:00:00:05')
    s.add_interface('eth5', '10:00:00:00:00:06')
    s.add_interface('eth6', '10:00:00:00:00:07')

    test_switch_to(s)
    # test_switch_lru(s)
    # test_switch_traffic(s)
    return s

def test_switch_to(s):
    # Overtime Removal
    case_1(s)
    for i in range(4):
        case_2(s)
        case_3(s)
    case_4(s)

def test_switch_lru(s):
    # LRU
    case_1(s)
    case_3(s)
    case_6(s)

def test_switch_traffic(s):
    # Least Traffic Removal
    case_1(s)
    case_3(s)
    case_5(s)


def case_1(s):
    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress

    testpkt = mk_pkt("ff:ff:ff:ff:ff:ff", "20:00:00:00:00:01")
    s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet),
             "An Ethernet frame with a broadcast destination address should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", testpkt, "eth2", testpkt, "eth3", testpkt, "eth4", testpkt, "eth5", testpkt, "eth6", testpkt, display=Ethernet),
             "The Ethernet frame with a broadcast destination address should be forwarded out other ports")

    testpkt = mk_pkt("20:00:00:00:00:01", "ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet),
             "An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, "eth3", testpkt, "eth4", testpkt, "eth5", testpkt, "eth6", testpkt, display=Ethernet),
             "The Ethernet frame with a broadcast destination address should be forwarded out other ports")


def case_2(s):
    # test case 2: a frame with any unicast address should be sent to the interface we previously leaned for it.
    reqpkt = mk_pkt("20:00:00:00:00:00", "20:00:00:00:00:01")
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:00 to 20:00:00:00:00:01 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:01 should be sent to eth1")

    resppkt = mk_pkt("20:00:00:00:00:01", "20:00:00:00:00:00")
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:01 to 20:00:00:00:00:00 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet),
             "Ethernet frame destined to 20:00:00:00:00:00 should be sent to eth0")

def case_3(s):
    # test case 3: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt("20:00:00:00:00:00", "10:00:00:00:00:01")
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet),
             "An Ethernet frame should arrive on eth2 with destination address the same as eth0's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0),
             "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")

    reqpkt = mk_pkt("20:00:00:00:00:00", "10:00:00:00:00:02")
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet),
             "An Ethernet frame should arrive on eth2 with destination address the same as eth1's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0),
             "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")

    reqpkt = mk_pkt("20:00:00:00:00:00", "10:00:00:00:00:03")
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
             "An Ethernet frame should arrive on eth2 with destination address the same as eth2's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0),
             "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")




def case_4(s):
    # test case 4: [for timeout] a frame with any unicast address that was removed from forwarding table should be learned again.

    # 4->6
    reqpkt = mk_pkt("20:00:00:00:00:04", "20:00:00:00:00:06")
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:04 to 20:00:00:00:00:06 should arrive on eth4")
    s.expect(PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth5", reqpkt, "eth6", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:06 should be flooded")

    # wait for 5.0s
    s.expect(PacketInputTimeoutEvent(5.0), "Wait for 5.0s.")

    # 6->4
    reqpkt = mk_pkt("20:00:00:00:00:06", "20:00:00:00:00:04")
    s.expect(PacketInputEvent("eth6", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:06 to 20:00:00:00:00:04 should arrive on eth6")
    s.expect(PacketOutputEvent("eth4", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:04 should be sent to eth4")

    # wait for 5.0s
    s.expect(PacketInputTimeoutEvent(5.0), "Wait for 5.0s.")

    # 6->4
    reqpkt = mk_pkt("20:00:00:00:00:06", "20:00:00:00:00:04")
    s.expect(PacketInputEvent("eth6", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:06 to 20:00:00:00:00:04 should arrive on eth6")
    s.expect(PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, "eth5", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:04 should be flooded")

    # wait for 8.0s
    s.expect(PacketInputTimeoutEvent(8.0), "Wait for 5.0s.")

    # 4->6
    reqpkt = mk_pkt("20:00:00:00:00:04", "20:00:00:00:00:06")
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:04 to 20:00:00:00:00:06 should arrive on eth4")
    s.expect(PacketOutputEvent("eth6", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:06 should be sent to eth6")

def case_5(s):
    # test case 4: [for least traffic] a frame with any unicast address that was removed from forwarding table should be learned again.

    for i in range(3):
        # 0->3
        reqpkt = mk_pkt("20:00:00:00:00:00", "20:00:00:00:00:03")
        s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
                 "An Ethernet frame from 20:00:00:00:00:00 to 20:00:00:00:00:03 should arrive on eth0")
        s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, "eth5", reqpkt, "eth6", reqpkt, display=Ethernet),
                 "Ethernet frame destined for 20:00:00:00:00:03 should be flooded")

    # 1->0
    reqpkt = mk_pkt("20:00:00:00:00:01", "20:00:00:00:00:00")
    s.expect(PacketInputEvent("eth1", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:01 to 20:00:00:00:00:00 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:00 should be sent to eth0")

    # 2->1
    reqpkt = mk_pkt("20:00:00:00:00:02", "20:00:00:00:00:01")
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:02 to 20:00:00:00:00:01 should arrive on eth2")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:01 should be sent to eth1")

    # 3->2
    reqpkt = mk_pkt("20:00:00:00:00:03", "20:00:00:00:00:02")
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:03 to 20:00:00:00:00:02 should arrive on eth3")
    s.expect(PacketOutputEvent("eth2", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:02 should be sent to eth2")

    # 4->0
    reqpkt = mk_pkt("20:00:00:00:00:04", "20:00:00:00:00:00")
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:04 to 20:00:00:00:00:00 should arrive on eth4")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:00 should be flooded")

    # 1->3
    reqpkt = mk_pkt("20:00:00:00:00:01", "20:00:00:00:00:03")
    s.expect(PacketInputEvent("eth1", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:01 to 20:00:00:00:00:03 should arrive on eth1")
    s.expect(PacketOutputEvent("eth3", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:03 should be sent to eth3")

    # 5->4
    reqpkt = mk_pkt("20:00:00:00:00:05", "20:00:00:00:00:04")
    s.expect(PacketInputEvent("eth5", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:05 to 20:00:00:00:00:04 should arrive on eth5")
    s.expect(PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, "eth6", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:04 should be flooded")

    # 5->3 and change port of 5 from eth5 to eth4, 4 is removed in this step
    reqpkt = mk_pkt("20:00:00:00:00:05", "20:00:00:00:00:03")
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:05 to 20:00:00:00:00:03 should arrive on eth4")
    s.expect(PacketOutputEvent("eth3", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:03 should be sent to eth3")


def case_6(s):
    # test case 6: [for LRU] a frame with any unicast address that was removed from forwarding table should be learned again.

    # 0->3
    reqpkt = mk_pkt("20:00:00:00:00:00", "20:00:00:00:00:03")
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
             "sender: eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, "eth5", reqpkt, "eth6",
                               reqpkt, display=Ethernet),
             "receiver: flooding")

    # 1->0
    reqpkt = mk_pkt("20:00:00:00:00:01", "20:00:00:00:00:00")
    s.expect(PacketInputEvent("eth1", reqpkt, display=Ethernet),
             "sender: eth1")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet),
             "receiver: eth0")

    # 2->0
    reqpkt = mk_pkt("20:00:00:00:00:02", "20:00:00:00:00:00")
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet),
             "sender: eth2")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet),
             "receiver: eth0")

    # 3->0
    reqpkt = mk_pkt("20:00:00:00:00:03", "20:00:00:00:00:00")
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet),
             "sender: eth3")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet),
             "receiver: eth0")

    # 4->0
    reqpkt = mk_pkt("20:00:00:00:00:04", "20:00:00:00:00:00")
    s.expect(PacketInputEvent("eth4", reqpkt, display=Ethernet),
             "sender: eth4")
    s.expect(PacketOutputEvent("eth0", reqpkt, display=Ethernet),
             "receiver: eth0")

    # 5->6
    reqpkt = mk_pkt("20:00:00:00:00:05", "20:00:00:00:00:06")
    s.expect(PacketInputEvent("eth5", reqpkt, display=Ethernet),
             "sender: eth5")
    s.expect(PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, "eth6",
                               reqpkt, display=Ethernet),
             "receiver: flooding")

    # 3->4
    reqpkt = mk_pkt("20:00:00:00:00:03", "20:00:00:00:00:04")
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet),
             "sender: eth3")
    s.expect(PacketOutputEvent("eth4", reqpkt, display=Ethernet),
             "receiver: eth4")

scenario = switch_tests()
