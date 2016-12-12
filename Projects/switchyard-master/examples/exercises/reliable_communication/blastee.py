#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
import time
import os

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    assert len(my_intf) == 1

    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + "/blastee_params.txt", "r") as fl:
            line = fl.readline().strip().split()
            i = 0
            while i < (len(line)):
                if line[i] == '-b':
                    i += 1
                    try:
                        end = line[i].find('/')
                        if end == -1:
                            blasterIP = IPv4Address(line[i])
                        else:
                            blasterIP = IPv4Address(line[i][:end])
                    except [IndexError, ValueError]:
                        break
                elif line[i] == '-n':
                    i += 1
                    try:
                        N = int(line[i])
                    except [IndexError, ValueError]:
                        break
                i += 1
    except FileNotFoundError:
        log_debug("No parameter settings.")
        return

    log_debug("N = {}".format(N))
    log_debug("blasterIP = {}".format(blasterIP))
    while True:
        gotpkt = True
        try:
            input_port_name,pkt = net.recv_packet()
            log_debug("Device is {}".format(input_port_name))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(input_port_name))
            log_debug("Pkt: {}".format(pkt))

            '''
            Creating the ACK packet headers for the packet
            '''
            ackPkt = Ethernet() + IPv4() + UDP()
            ackPkt[1].protocol = IPProtocol.UDP

            ackPkt[0].src = mymacs[0]
            ackPkt[0].dst = '10:00:00:00:00:01'
            ackPkt[1].srcip = myips[0]
            ackPkt[1].dstip = blasterIP
            ackPkt[2].srcport = 8
            ackPkt[2].dstport = 13
            log_debug("size of pkg = {}".format(len(pkt._headers)))
            temp = pkt.get_header(RawPacketContents).to_bytes()
            seqNumber = int.from_bytes(temp[:4], 'big')
            log_debug("sequence number = {}".format(seqNumber))
            if seqNumber > N:
                break
            ackPkt += temp[:4]

            length = int.from_bytes(temp[4:6], 'big')
            if length < 8:
                # padding
                payload = temp[6:].ljust(8, b'\0') #ackPkt += temp[6:6+length] + bytes(8-length)
            else:
                payload = temp[6:14]
            ackPkt += payload
            log_debug("ackPkt = {}".format(ackPkt))
            assert input_port_name == 'blastee-eth0'
            net.send_packet(input_port_name, ackPkt)

    net.shutdown()
