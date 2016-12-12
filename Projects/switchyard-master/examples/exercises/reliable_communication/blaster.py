#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from random import randint
import time
import os


def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    assert len(my_intf) == 1

    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + "/blaster_params.txt", "r") as fl:
            line = fl.readline().strip().split()
            i = 0
            while i < (len(line)):
                if line[i] == '-b':
                    i += 1
                    try:
                        end = line[i].find('/')
                        if end == -1:
                            blasteeIP = IPv4Address(line[i])
                        else:
                            blasteeIP = IPv4Address(line[i][:end])
                    except [IndexError, ValueError]:
                        break
                elif line[i] == '-n':
                    i += 1
                    try:
                        N = int(line[i])
                    except [IndexError, ValueError]:
                        break
                elif line[i] == '-l':
                    i += 1
                    try:
                        L = int(line[i])
                    except [IndexError, ValueError]:
                        break
                elif line[i] == '-w':
                    i += 1
                    try:
                        SW = int(line[i])
                    except [IndexError, ValueError]:
                        break
                elif line[i] == '-t':
                    i += 1
                    try:
                        timeout = float(line[i])/1000
                    except [IndexError, ValueError]:
                        break
                elif line[i] == '-r':
                    i += 1
                    try:
                        recv_timeout = float(line[i])
                    except [IndexError, ValueError]:
                        break
                i += 1

    except FileNotFoundError:
        log_debug("No parameter settings.")
        return

    def send_packet(n):
        '''
        Creating the headers for the packet
        '''
        pkt = Ethernet() + IPv4() + UDP()
        pkt[1].protocol = IPProtocol.UDP

        '''
        Do other things here and send packet
        '''
        pkt[0].src = mymacs[0]
        pkt[0].dst = EthAddr('20:00:00:00:00:01')
        pkt[1].srcip = myips[0]
        pkt[1].dstip = IPv4Address(blasteeIP)
        pkt[2].srcport = 73
        pkt[2].dstport = 99

        pkt += n.to_bytes(4, 'big') + L.to_bytes(2, 'big')
        payload = b'hello world'.ljust(L) #bytes(L)
        pkt += payload
        assert my_intf[0].name == "blaster-eth0"
        net.send_packet(my_intf[0].name, pkt)

    # blasteeIP = IPv4Address('192.168.200.1')
    # N = 10
    # L = 100
    # SW = 5
    # timeout = 20000
    # recv_timeout = 2

    LHS = 1
    RHS = 1

    pktNotAcked = set()
    lastTime = time.time()

    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            dev,pkt = net.recv_packet(timeout=recv_timeout)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            ## get self-defined packet header
            temp = pkt[3].to_bytes()

            ## update set of non-acked packets
            seqNumber = int.from_bytes(temp[:4], 'big')
            if seqNumber in pktNotAcked:
                pktNotAcked.remove(seqNumber)

            ## update LHS
            start = LHS
            if seqNumber == LHS:
                while LHS not in pktNotAcked and LHS < RHS:
                    LHS += 1
                    if LHS == start + SW:
                        assert len(pktNotAcked) == 0
                    lastTime = time.time()
        else:
            log_debug("Didn't receive anything")

        if LHS == N+1 and len(pktNotAcked) == 0:
            break
        ## send next packet
        if RHS - LHS + 1 <= SW and RHS <= N:
            send_packet(RHS)
            pktNotAcked.add(RHS)
            RHS += 1

        ## check timeout
        if time.time() - lastTime >= timeout and len(pktNotAcked) > 0:
            ## resend all unacked packets
            for seqNumber in pktNotAcked:
                send_packet(seqNumber)
            lastTime = time.time()

        log_debug("--------------------------Status-----------------------------")
        log_debug("LHS = {}, RHS = {}".format(LHS, RHS))
        log_debug("# unacked pkts = {}".format(pktNotAcked))

    net.shutdown()
