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
		print(ans)
		print ("\n[*] IP - MAC") 
		for snd,rcv in ans: 
			#print(rcv.sprintf(r"%ARP.psrc% - %Ether.src%"))
			list_arp.append(rcv.sprintf(r"%ARP.psrc% - %Ether.src%"))
			print(rcv.split())
		return list_arp
		"""stop_time = datetime.now()
		total_time = stop_time - start_time 
		print("\n[*] Scan Complete. Duration:", total_time)

	if __name__ == "__main__":
		arp_scan(sys.argv[1], sys.argv[2])"""

scan = ArpScan.arp_scan(sys.argv[1], sys.argv[2])

print(scan)