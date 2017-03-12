# DNS-Rejector


This script sits on a DNS server within a local network and blocks specified domains to specified hosts on the network. Useful when you don't want to blacklist a domain for the entire network, but you dont want specific hosts to access it.

# Usage

You want to block google.com, yahoo.com, and reddit.com from hosts 192.168.1.1 and 192.168.1.2
```bash
python main.py --domain google.com yahoo.com reddit.com --hosts 192.168.1.1 192.168.1.2
```

If you wanted to redirect a specific host visiting google.com to a specific redirector (192.168.1.100)
```bash
python main.py --domain google.com --hosts 192.168.1.1 --spoof 192.168.1.100
```

# Dependencies

This requires the 0.4-3 version of python-nfqueue. sudo apt install python-nfqueue will return version >.5 so use these commands to download and put an upgrade hold on the 0.4-3 version of python-nfqueue

```bash
cd /tmp
wget http://launchpadlibrarian.net/106081585/python-nfqueue_0.4-3_amd64.deb
sudo dpkg -i python-nfqueue_0.4-3_amd64.deb
sudo apt-mark hold python-nfqueue
```

# Persistence

Add a root cronjob entry to check for existance and if not, execute.
```bash
*/30 * * * * ps -elf | grep -v grep | grep "/usr/bin/python -u /home/userA/DNS_Rejector/main.py" >> /dev/null ||  /usr/bin/python -u /home/userA/DNS_Rejector/main.py --domain google.com yahoo.com --hosts 192.168.1.1 192.168.1.2 > /var/log/DNS_Redirection.log 2>&1 &
```

# Future Plans

Block/redirect all domains from specified hosts.

Block all domains except for whitelisted domains.

Block specified domains on all hosts.


































































































































































































