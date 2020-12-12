# DNS-and-DNSSEC-resolver
# DNS resolver by python3

How to run:

The code has been tested under python 3.7.1, not sure about other python versions.

To run mydig.py, type in "python mydig.py <domain> <dnsType>" 
To run dnssec.py, type in "python dnssec.py <domain> <dnsType>"

For the domains that support and implemented DNSSEC, the dnssec.py will give out
final answer, otherwise it will output what specific situation has been encountered.


The library I used:
Mydig.py:
import dns.query
import dns.message
import dns.name
import dns.flags
import sys
import time

Dnssec.py:
import dns.query
import dns.message
import dns.name
import dns.flags
import dns.dnssec
import sys
import time
