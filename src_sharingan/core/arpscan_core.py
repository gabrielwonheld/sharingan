import sys
from scapy.all import srp, Ether, ARP, conf


class ArpScan:

	@staticmethod
	def arp_scan(interface, ips):

		print("[*] Scanning...")
		list_arp = []
		conf.verb = 0
		ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips),
				timeout = 2,
				iface = interface,
				inter = 0.1)
		print ("\n[*] IP - MAC")
		for snd,rcv in ans:
			ip = rcv[ARP].psrc
			mac = rcv[Ether].src
			list_arp.append((ip,mac))
		return list_arp


# Only runs when the module is executed directly (`python core/arpscan_core.py <iface> <ips>`).
# It used to sit loose at module level, which triggered a real ARP scan on every `import`
# (including during test collection).
if __name__ == '__main__':
	scan = ArpScan.arp_scan(sys.argv[1], sys.argv[2])
	print(scan)