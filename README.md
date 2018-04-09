# DNS-Rejector


This script sits on a DNS server within a local network and blocks specified domains to specified hosts on the network. Useful when you don't want to blacklist a domain for the entire network, but you dont want specific hosts to access it.

# Usage

You want to block google.com, yahoo.com, and reddit.com from hosts 192.168.1.1 and 192.168.1.2. 

Note: do not include wildcards in the domains you want blacklisted. Just include the basic domain name. (E.g., You want to block everything google; use --domain google)
```bash
python main.py --domains google.com yahoo.com reddit.com --hosts 192.168.1.1 192.168.1.2
```

If you wanted to redirect a specific host visiting google.com to a specific redirector (192.168.1.100)
```bash
python main.py --domains google.com --hosts 192.168.1.1 --spoof 192.168.1.100
```

Block all domains for a specific host
```bash
python main.py --domains '*' --hosts 192.168.1.1
```

Block specific domains for all hosts
```bash
python main.py --domains google.com --hosts '*'
```

Block all domains for all hosts expect for google.com
```bash
python main.py --domains '*' --hosts '*' --whitelist google.com
```

Block different domains for different hosts
```bash
python main.py --combined_blacklist 192.168.1.1,192.168.1.2:youtube --combined_blacklist 192.168.1.3:yahoo
```

# Dependencies

This requires the NetfilterQueue 0.8.1

```bash
pip install NetfilterQueue
```

# Persistence

Add a root cronjob entry to check for existance and if not, execute.
```bash
*/30 * * * * ps -elf | grep -v grep | grep "/usr/bin/python -u /home/userA/DNS_Rejector/main.py" >> /dev/null ||  /usr/bin/python -u /home/userA/DNS_Rejector/main.py --domain google.com yahoo.com --hosts 192.168.1.1 192.168.1.2 > /var/log/DNS_Redirection.log 2>&1 &
```

# Future Plans

~~Block/redirect all domains from specified hosts.~~

~~Block all domains except for whitelisted domains.~~

~~Block specified or all domains on all hosts.~~


































































































































































































