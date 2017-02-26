#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Created: 2017-02-22
# Author: Johnathan
#
# Distributed under terms of the MIT license.
# Requires python-nfqueue 0.4-3

import time
import nfqueue
import os
import subprocess as sp
from socket import getfqdn
from scapy.all import *

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')


domain = ['nastydomain','baddomain']
iptables_table = 'dns_reject'
ip_address = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']
redirect_ip = '192.168.1.50'

def clean_iptables(table_name):
        try:
                sp.check_call(['iptables','-L',table_name], stdout=DEVNULL, stderr=DEVNULL)
                sp.Popen(['iptables', '-D', 'INPUT', '-j', table_name], stdout=DEVNULL, stderr=DEVNULL)
                sp.Popen(['iptables', '-F', table_name], stdout=DEVNULL, stderr=DEVNULL)
                sp.Popen(['iptables', '-X', table_name], stdout=DEVNULL, stderr=DEVNULL)
        except sp.CalledProcessError as err:
                pass


def create_iptables(table_name, ips):
        sp.Popen(['iptables', '-N', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen(['iptables', '-A', 'INPUT', '-j', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen(['iptables', '-A', table_name, '-s', ','.join(ips), '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE'], stdout=DEVNULL, stderr=DEVNULL)


def callback(payload):
    global redirect_ip
    data = payload.get_data()
    pkt = IP(data)
    if not pkt.haslayer(DNSQR):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        for d in domain:
                if d in pkt[DNS].qd.qname:
                        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                                  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                                  DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=redirect_ip))
                        payload.set_verdict(nfqueue.NF_DROP)
                        send(spoofed_pkt, verbose=0)
                        print "{} *SPOOFED* {:<30} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:28], getfqdn(pkt[IP].src))
                        return
        print "{} {:<40} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:38], getfqdn(pkt[IP].src))



def main():
    clean_iptables(iptables_table)
    create_iptables(iptables_table, ip_address)
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        clean_iptables(iptables_table)
        sys.exit('Closing...')

if __name__ == '__main__':
    main()

