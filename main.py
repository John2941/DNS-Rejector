#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Created: 2017-02-22
# Author: Johnathan
#
# Note: Possible issue when blacklisting all domains and trying to resolve the host's fqdn
#
# Distributed under terms of the MIT license.
# Requires python-nfqueue 0.4-3

import time
import argparse
import os
import subprocess as sp
import logging
import sys
from socket import getfqdn, socket
from collections import defaultdict
from netfilterqueue import NetfilterQueue

try:
    from scapy.all import *
except ImportError:
    from scapy import *
try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

DOMAIN_BLOCK_DICT = defaultdict(list)
DOMAIN_WHITELIST_DICT = defaultdict(list)
blacklist = None
whitelist = None

parser = argparse.ArgumentParser()
parser.add_argument('--domains', dest='domains', action='store', nargs='+', default=[], required=False, type=str,
                    help='List of domains to block. Use \'*\' to block all domains.')
parser.add_argument('--hosts', dest='hosts', action='store', nargs='+', default=[], required=False, type=str,
                    help='List of the IP addresses from hosts to be blacklisted. Use \'*\' to select all hosts.')
parser.add_argument('--spoof', dest='redirect_ip', action='store', default='192.168.2.98', required=False,
                    type=str, help='The response IP address of the spoofed packets.')
parser.add_argument('--whitelist', dest='whitelist', action='store', nargs='+', default=[], required=False, type=str,
                    help='Domains to be excluded when the wildcard is applied to the --domain arg.')
parser.add_argument('--combined_blacklist', dest='combined_blacklist', action='store', nargs='+', default=[], required=False, type=str,
                    help='Domain and host specific DNS blocking. \nUsage: --combined google:192.168.2.1,192.168.2.2 \
                    --combined yahoo:192.168.2.1')
parser.add_argument('--combined_whitelist', dest='combined_whitelist', action='store', nargs='+', default=[], required=False, type=str,
                    help='Domain and host specific DNS blocking. \nUsage: --combined google:192.168.2.1,192.168.2.2 \
                    --combined yahoo:192.168.2.1')
parser.add_argument('--debug', dest='debug', action='store_true', required=False, help='Enable debug logging to console.')
args = parser.parse_args()

log = logging.getLogger(__name__)

if args.debug:
    log.setLevel(logging.DEBUG)
else:
    log.setLevel(logging.INFO)

formatter = logging.Formatter('%(levelname)s: %(message)s')

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)

log.addHandler(ch)


class DomainList(defaultdict):
    def add(self, *args):
        for ip, domain in args:
            self[ip].append(domain)

    def items(self):
        return [(key, self[key]) for key in self]

    def __str__(self):
        return str(self.items())
        #return ', '.join(str(h + ' ' + d) for h, d in self.items())

    def __contains__(self, item):
        '''
        :param item: (IP_ADDRESS, FQDN)
        :return: True IP == IP and domain in FQDN
        '''
        h = item[0]
        d = item[1]
        for ip, domain in self.items():
            for dom in domain:
                if (h == ip or ip == '*') and (dom in d or dom == '*'):
                    return True
        return False

# The IPTable's chain your prepending to depends on where your DNS service is hosted on the machine.
#       If your DNS service is hosted on the machine, you'll be prepending to the INPUT chain.
#       However, if your DNS packets are being FORWARD to another service
#       (i.e., a docker container that uses a bridge network adapter) then you'll need to prepend to the FORWARD chain

def clean_iptables(table_name):
    iptables_bin = '/sbin/iptables'
    try:
        sp.check_call([iptables_bin, '-L', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen([iptables_bin, '-D', 'FORWARD', '-j', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen([iptables_bin, '-F', table_name], stdout=DEVNULL, stderr=DEVNULL)
        sp.Popen([iptables_bin, '-X', table_name], stdout=DEVNULL, stderr=DEVNULL)
    except sp.CalledProcessError as err:
        pass


def create_iptables(table_name, ips):
    iptables_bin = '/sbin/iptables'
    sp.Popen([iptables_bin, '-N', table_name], stdout=DEVNULL, stderr=DEVNULL)
    sp.Popen([iptables_bin, '-I', 'FORWARD', '-j', table_name], stdout=DEVNULL, stderr=DEVNULL)
    if '*' in ips:
        rule = [iptables_bin, '-A', table_name, '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE', '--queue-num', '1']
        log.debug("IPTABLE RULE: {}".format(' '.join(rule)))
        sp.Popen(rule,
                 stdout=DEVNULL, stderr=DEVNULL)
    else:
        rule = [iptables_bin, '-A', table_name, '-s', ','.join(ips), '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE', '--queue-num', '1']
        log.debug("IPTABLE RULE: {}".format(' '.join(rule)))
        sp.Popen([iptables_bin, '-A', table_name, '-s', ','.join(ips), '-p', 'udp', '--dport', '53', '-j', 'NFQUEUE', '--queue-num', '1'],
                 stdout=DEVNULL, stderr=DEVNULL)

def build_domain_list(**kwargs):
    '''
    **Kwargs
    combined_hosts_and_domains=
    domains=
    hosts=
    Builds domain block list with applicable hosts
    :return: DomainList object
    '''

    domain_list = DomainList(list)
    combined_hosts_and_domains = kwargs['combined_hosts_and_domains']
    domains = kwargs['domains']
    hosts = kwargs['hosts']

    if combined_hosts_and_domains:
        for domain_arg in combined_hosts_and_domains:
            host, domain = domain_arg.split(':')
            domain = domain.split(',')
            host = host.split(',')
            for h in host:
                domain_list[h].extend(domain)
    if domains:
        for h in hosts:
            domain_list[h].extend(domains)

    return domain_list


def callback(payload):
    global blacklist
    global whitelist
    pkt = IP(payload.get_payload())
    # print "{} {:<40} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:38], getfqdn(pkt[IP].src))
    if not pkt.haslayer(DNSQR):
        payload.accept()
    else:
        log.debug("{} searching for {}".format(pkt[IP].src, pkt[DNS].qd.qname))
        log.debug('{} in blacklist: {}'.format(pkt[DNS].qd.qname, (pkt[IP].src, pkt[DNS].qd.qname) in blacklist))
        log.debug('Destination addr: {}'.format(pkt[IP].dst))
        # Your IPTable rules will drop your spoofed packets depending on your network configuration.
        #       If you are PREROUTING packets to a docker container for example, you'll have to explicitly define the
        #               src packet as the machine hosting the docker container and not the source
        #               of the packet as its src will have
        #               already been changed by the PREROUTING chain.
        #       If your DNS service is hosted on the machine where this script is running
        #           then you can set IP(src=pkt[IP].dst)
        if (pkt[IP].src, pkt[DNS].qd.qname) in blacklist and (pkt[IP].src, pkt[DNS].qd.qname) not in whitelist:
            spoofed_pkt = IP(dst=pkt[IP].src, src=args.redirect_ip) / \
                          UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                              an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=args.redirect_ip))
            #payload.set_verdict(nfqueue.NF_DROP)
            payload.drop()
            send(spoofed_pkt, verbose=0)
            print "{} *SPOOFED* {:<30} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:28],
                                                     getfqdn(pkt[IP].src))
            return
        print "{} {:<40} -> {}".format(time.strftime("%Y-%m-%d %H:%M"), pkt[DNS].qd.qname[:38], getfqdn(pkt[IP].src))


def main():
    if os.getgid():
        print("NFQUEUE requires root permissions.")
        sys.exit(1)
    #if args.whitelist and args.domains != ['*']:
    #    print('USAGE: --domains \'*\' --whitelist domain1')
    #    sys.exit(1)

    iptables_table = 'dns_reject'
    clean_iptables(iptables_table)

    log.debug('args.combined_blacklist: {}'.format(args.combined_blacklist))
    log.debug('args.hosts: {}'.format(args.hosts))
    log.debug('args.domains: {}'.format(args.domains))

    global blacklist
    blacklist = build_domain_list(
        combined_hosts_and_domains=args.combined_blacklist,
        domains=args.domains,
        hosts=args.hosts
    )

    global whitelist
    whitelist = build_domain_list(
        combined_hosts_and_domains=args.combined_whitelist,
        domains=args.whitelist,
        hosts=['*']
    )
    log.debug('Blacklist: {}'.format(blacklist))
    log.debug('Whitelist: {}'.format(whitelist))
    log.debug('Creating IPTable rules for {}'.format(','.join(set(blacklist.keys()))))
    create_iptables(iptables_table, set(blacklist.keys()))

    q = NetfilterQueue()
    q.bind(1, callback)
    s = socket.fromfd(q.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        #q.try_run()  # Main loop
        q.run_socket(s)
    except KeyboardInterrupt:
        s.close()
        q.unbind()
        clean_iptables(iptables_table)
        sys.exit('Closing...')


if __name__ == '__main__':
    main()
