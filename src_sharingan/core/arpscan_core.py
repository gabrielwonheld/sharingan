import sys
from datetime import datetime
from scapy.all import srp,Ether,ARP,conf 

class ArpScan:

	def arp_scan(interface, ips):

		print("[*] Scanning...") 
		#start_time = datetime.now()
		list_arp = []
		conf.verb = 0 
		ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), 
				timeout = 2, 
				iface = interface,
				inter = 0.1)
		#print(ans)
		print ("\n[*] IP - MAC") 
		for snd,rcv in ans: 
			ip = rcv[ARP].psrc
			mac = rcv[Ether].src
			#print(rcv.sprintf(r"%ARP.psrc% - %Ether.src%"))
			list_arp.append((ip,mac))
			#print(rcv)
		return list_arp

scan = ArpScan.arp_scan(sys.argv[1], sys.argv[2])

print(scan)