#!/usr/bin/env python

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

    # case_1(s)
    # case_2(s)
    # case_3(s)
    case_4(s)
    return s

def case_1(s):
    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress

    testpkt = mk_pkt("ff:ff:ff:ff:ff:ff", "30:00:00:00:00:02")
    s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet),
             "An Ethernet frame with a broadcast destination address should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", testpkt, "eth2", testpkt, display=Ethernet),
             "The Ethernet frame with a broadcast destination address should be forwarded out ports eth1 and eth2")

    testpkt = mk_pkt("30:00:00:00:00:02", "ff:ff:ff:ff:ff:ff")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet),
             "An Ethernet frame with a broadcast destination address should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, display=Ethernet),
             "The Ethernet frame with a broadcast destination address should be forwarded out ports eth0 and eth2")


def case_2(s):
    # test case 2: a frame with any unicast address should be sent to the interface we previously leaned for it.
    reqpkt = mk_pkt("20:00:00:00:00:01", "30:00:00:00:00:02")
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:01 to 30:00:00:00:00:02 should arrive on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, display=Ethernet),
             "Ethernet frame destined for 30:00:00:00:00:02 should be sent to eth1")

    resppkt = mk_pkt("30:00:00:00:00:02", "20:00:00:00:00:01")
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet),
             "An Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 should arrive on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet),
             "Ethernet frame destined to 20:00:00:00:00:01 should be sent to eth0")

def case_3(s):
    # test case 3: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt("20:00:00:00:00:01", "10:00:00:00:00:01")
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet),
             "An Ethernet frame should arrive on eth2 with destination address the same as eth0's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0),
             "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")

    reqpkt = mk_pkt("20:00:00:00:00:01", "10:00:00:00:00:02")
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet),
             "An Ethernet frame should arrive on eth2 with destination address the same as eth1's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0),
             "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")

    reqpkt = mk_pkt("20:00:00:00:00:01", "10:00:00:00:00:03")
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet),
             "An Ethernet frame should arrive on eth2 with destination address the same as eth2's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0),
             "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")

def case_4(s):
    # test case 4: a frame with any unicast address that was removed from forwarding table after some time limit should learned again.
    s.add_interface('eth3', '10:00:00:00:00:04')
    s.add_interface('eth4', '10:00:00:00:00:05')
    s.add_interface('eth5', '10:00:00:00:00:06')


    reqpkt = mk_pkt("20:00:00:00:00:03", "20:00:00:00:00:04")
    s.expect(PacketInputEvent("eth3", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:03 to 20:00:00:00:00:04 should arrive on eth3")
    s.expect(PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, "eth2", reqpkt, "eth4", reqpkt, "eth5", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:04 should be flooded out eth0, eth1, eth2, eth4, eth5")

    reqpkt = mk_pkt("20:00:00:00:00:05", "20:00:00:00:00:03")
    s.expect(PacketInputEvent("eth5", reqpkt, display=Ethernet),
             "An Ethernet frame from 20:00:00:00:00:05 to 20:00:00:00:00:03 should arrive on eth5")
    s.expect(PacketOutputEvent("eth3", reqpkt, display=Ethernet),
             "Ethernet frame destined for 20:00:00:00:00:03 should be sent to eth3")

    # reqpkt = mk_pkt("20:00:00:00:00:05", "20:00:00:00:00:03")
    # s.expect(PacketInputEvent("eth5", reqpkt, display=Ethernet),
    #          "An Ethernet frame from 20:00:00:00:00:05 to 20:00:00:00:00:03 should arrive on eth5")
    # s.expect(PacketOutputEvent("eth0", reqpkt, "eth1", reqpkt, "eth2", reqpkt, "eth3", reqpkt, "eth4", reqpkt, display=Ethernet),
    #          "Ethernet frame destined for 20:00:00:00:00:03 should be blooded out eth0, eth1, eth2, eth3, eth4")



scenario = switch_tests()
