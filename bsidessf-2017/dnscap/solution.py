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