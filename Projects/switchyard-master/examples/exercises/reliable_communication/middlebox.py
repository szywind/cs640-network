#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
from random import randint
import time
import random
import os

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    try:
        dir_path = os.path.dirname(os.path.realpath(__file__))
        with open(dir_path + "/middlebox_params.txt", "r") as fl:
            line = fl.readline().strip().split()
            i = 0
            while i < len(line):
                if line[i] == '-d':
                    i += 1
                    dropRate = float(line[i])
                i += 1
    except FileNotFoundError:
        log_debug("No parameter settings.")
        return

    while True:
        gotpkt = True
        try:
            dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet {}".format(pkt))

            if dev == "middlebox-eth0":
                log_debug("Received from blaster")
                '''
                Received data packet
                Should I drop it?
                If not, modify headers & send to blastee
                '''

                rv = random.random()
                if(rv < dropRate):
                    log_debug("Drop the packet")
                else:
                    ether = pkt.get_header(Ethernet)
                    ether.src = '40:00:00:00:00:02'
                    ether.dst = '20:00:00:00:00:01'
                    net.send_packet("middlebox-eth1", pkt)
            elif dev == "middlebox-eth1":
                log_debug("Received from blastee")
                '''
                Received ACK
                Modify headers & send to blaster. Not dropping ACK packets!
                net.send_packet("middlebox-eth0", pkt)
                '''
                ether = pkt.get_header(Ethernet)
                ether.src = '40:00:00:00:00:01'
                ether.dst = '10:00:00:00:00:01'
                net.send_packet("middlebox-eth0", pkt)
            else:
                log_debug("Oops :))")

    net.shutdown()
