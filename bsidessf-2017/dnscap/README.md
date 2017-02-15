# BsidesSF 2017 - Dnscap (forensics, 500 pts)

>Found this packet capture. Pretty sure there's a flag in here. Can you find it!?

>[dnscap.pcap](dnscap.pcap)

We get a packet capture containing DNS traffic. Only queries and replies for A, MX and TXT records. We thought about an exchange over a DNS tunnel but didn't really know where to start. We simply started by decoding the hostnames in the DNS queries and see what it looked like:

```python
from scapy.all import rdpcap, DNSQR, DNSRR

for p in rdpcap('dnscap.pcap'):

	# Look at queries only
	if p.haslayer(DNSQR) and not p.haslayer(DNSRR):

		qry = p[DNSQR].qname.replace('.skullseclabs.org.', '').split('.')
		qry = ''.join(_.decode('hex') for _ in qry)

		print '%r' % qry
```

The data in the hostnames towards the end contained this:

    '\xa0W\x00\xe6\xda\x83Q\x00\x01console (sirvimes)\x00'
    '\xb5A\x01\xe6\xda\x83Qn\xa2'
    '1s\x01\xe6\xda\x83Qn\xa2'
    '\xac\xe3\x01\xe6\xda\x83Qn\xa2Good luck! That was dnscat2 traffic on a flaky connection with lots of re-transmits. Seriously, '
    'd[\x01\xe6\xda\x83\xb1n\xa2good luck. :)\n'
    '3z\x01\xe6\xda\x83\xbfn\xa2'
    'T[\x01\xe6\xda\x83\xbfn\xa2'

From the message above we deducted that we were probably looking at the right place, and the first 9 bytes of each request was probably some dnscat specific data, useless for us. So we ran the script again, skipping the first 9 bytes and could observe the following:

![](https://i.imgur.com/qfAckUa.png)

We can clearly recognise the signature for a PNG file being transmitted! We adapted our script to skip the first 9 bytes of each decoded hostname in the queries, and take only the lines between this PNG file header and the one that contained the 'IEND' chunk:

```python
	if 15 < qry_nb < 194:
		out += qry[9:]

	qry_nb += 1

open('out.png', 'wb').write(out)
```

At this point, the file was ineligible. After mucking around trying to fix it, we remembered the phrase that we saw before: *"That was dnscat2 traffic on a flaky connection with lots of re-transmits."*

That would mean that a lot of queries were actually the same as the previous ones? Let's try and fix the script. We also need to remove another 9 bytes of garbage in the first query that contains the PNG header. Finally our [script](solution.py) below solved it!

```python
from scapy.all import rdpcap, DNSQR, DNSRR

last_qry = ''
out = ''
q_nb = 0

for p in rdpcap('dnscap.pcap'):

	if p.haslayer(DNSQR) and not p.haslayer(DNSRR):

		qry = p[DNSQR].qname.replace('.skullseclabs.org.', '').split('.')
		qry = ''.join(_.decode('hex') for _ in qry)[9:]

		if qry == last_qry:
			continue

		last_qry = qry
		q_nb += 1

		if q_nb == 7: # packet with PNG header
			out += qry[8:]

		if 7 < q_nb < 127: # All packets up to IEND chunk
			out += qry

open('flag.png', 'wb').write(out)
```
Running it yields a valid PNG:
  
![](flag.png?raw=true)
