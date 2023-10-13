import argparse
import textwrap
import ipaddress
import subprocess
import datetime
import time
import re
import locale
import sys
import os
from ipaddress import ip_address
from sys import platform
import concurrent.futures
from threading import Thread
if "darwin" in platform:
     import resource # pylint: disable=import-error

version = "0.4.4"
alive = []                              #Empty list to collect reachable hosts
alive_avg = []                          #Empty list to collect reachable hosts + RTT
dead = []                          #Empty list to collect unreachable hosts
unknown = []                           #Empty list to collect Unknown hosts

os.system("")

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   GRAY = '\033[90m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def ipsorter(s):
    try:
        ip = int(ip_address(s))
    except ValueError:
        return (1, s)
    return (0, ip)

def ping_test (ip,ping_count):
    if "win32" in platform:                   #platform equals win32 for Windows, equals linux for Linux, darwin for Mac
        if locale.getdefaultlocale()[0] == 'zh_CN':
            pattern = r"平均 = (\d+\S+)"
            pattern_ip = r"\[\d+.\d+.\d+.\d+\]"
            pattern_rtt = r"最短 = (\d+ms).+最长 = (\d+ms).+平均 = (\d+ms)"
            keyword = "平均"
            ping_test = subprocess.Popen(["ping", "-n", ping_count, ip], stdout = subprocess.PIPE,stderr = subprocess.PIPE,encoding='cp936')
            origin_strs = ping_test.stdout.read() # 得到的是 bytes ====》 b'字符串内容'
            s = str(origin_strs)  # --> bytes 2 string
        else:
            pattern = r"Average = (\d+\S+)"
            pattern_ip = r"\[\d+.\d+.\d+.\d+\]"
            pattern_rtt = r"Minimum = (\d+ms), Maximum = (\d+ms), Average = (\d+ms)"
            keyword = "Average"
            ping_test = subprocess.Popen(["ping", "-n", ping_count, ip], stdout = subprocess.PIPE,stderr = subprocess.PIPE)
    elif "darwin" in platform:                 #Linux & Mac
        pattern = r"= \d+\.\d+/(\d+\.\d+)/\d+\.\d+/\d+\.\d+ ms"
        pattern_rtt = r"= (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/\d+\.\d+ ms"
        pattern_ip = r"\(\d+.\d+.\d+.\d+\)"
        keyword = "avg"
        ping_test = subprocess.Popen(["ping", "-t 4","-c", ping_count, ip], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    else:
        pattern = r"= \d+\.\d+/(\d+\.\d+)/\d+\.\d+/\d+\.\d+ ms"
        pattern_rtt = r"= (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)/\d+\.\d+ ms"
        pattern_ip = r"\(\d+.\d+.\d+.\d+\)"
        keyword = "avg"
        ping_test = subprocess.Popen(["ping", "-W 4","-c", ping_count, ip], stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    output = ping_test.communicate()[0]
    output_str = str(output)
    if "win32" in platform and locale.getdefaultlocale()[0] == 'zh_CN':
        output_str = s
    if keyword in output_str:                #If Average latency is available, it's reachable
        try:
            ipaddress.ip_address(ip)           #Check if it's an IP address
            type = "ip"
        except ValueError:                      
            type = "hostname"
        avg = re.findall(pattern, output_str)[0]   #Regex to find latency
        rtt = re.findall(pattern_rtt, output_str)[0]
        
        if "linux" in platform or "darwin" in platform:              
            rtt_i = [0, 2, 1]
            rtt = [rtt[i]+"ms" for i in rtt_i]               #reorder to min/max/avg for linux&mac
            avg = avg+"ms"
        if type == "ip":
            print("IP: {0:49} {1:>9}  {2:>9}  {3:>9}".format(ip, rtt[0],rtt[1],rtt[2]))
        else:                                   
            ipadd = re.findall(pattern_ip,output.decode())[0]       #if type is hostname, add resolved IP address
            print("Host: {0:47} {1:>9}  {2:>9}  {3:>9}".format(ip+" "+ipadd,rtt[0],rtt[1],rtt[2]))
        alive.append(ip)
        alive_avg.append("{0:41} RTT:{1}".format(ip, avg))
    elif "could not find host" in output_str or "nknown host" in output_str or "not known" in output_str:      #unknown hosts
        unknown.append(ip)
    else:
        dead.append(ip)            #Else, it's not reachable

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file", nargs="?", action="store", help="specify text file that stores CIDR/hostname/IP")
    group.add_argument("address", nargs="?", default=[], help= textwrap.dedent('''CIDR/hostname/IP
Example:
    pingnet 192.168.1.0/24
    pingnet www.google.com
    pingnet 8.8.8.8 '''))
    parser.add_argument("-n", "--count", nargs="?", action="store", help="number of echo requests to send, default 3")
    parser.add_argument("-w", "--write", action="store_true", help="write results to txt files")
    parser.add_argument("-V", "--version", action="version", version="PingNet "+version)
    args = parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    ping_count = args.count if args.count else "3" 
    print("\n"+" "*34+color.BOLD + "PingNet [v"+version+"]" + color.END)
    if "darwin" in platform:            #set "ulimit -n" higher for Mac, to avoid "OSError: [Errno 24] Too many open files"
        target_procs=50000
        cur_proc, max_proc=resource.getrlimit(resource.RLIMIT_NOFILE)
        target_proc = min(max_proc,target_procs)
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(cur_proc,target_proc),max_proc))

    if "win32" in platform:
        import ctypes
        ctypes.windll.msvcrt._setmaxstdio(2048)
    date = datetime.date.today()
    now = datetime.datetime.now()
    
    print("Number of ping requests: {0:41}{1}".format(ping_count,now.strftime("%Y/%m/%d %H:%M:%S")),end="")
    start_time = time.time()                 
    print("\nIP/Host {0:51} Min        Max        Avg {1}".format("",""))
    print("-------------------------------------------------------------------------------------")
    thread_list = []                        
    totalAddress = 0                              #total address count

    if args.file:                             #if argument -f is specified
        f = open(args.file, 'r')  # open file
        thread_list = []
        max_threads = 1024
        def ping_all(ip_address):
            ping_test(str(ip_address), ping_count)

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            for line in f:
                if line != "\n" and not line.startswith("#"):
                    IP = line.strip().split("#", 1)[0].rstrip()
                    if "/" in IP:
                        for ip in ipaddress.IPv4Network(IP, False):
                            totalAddress += 1
                            thread_list.append(executor.submit(ping_all, str(ip)))
                    else:
                        totalAddress += 1
                        thread_list.append(executor.submit(ping_all, IP))
        for th in concurrent.futures.as_completed(thread_list):
            th.result()

    if args.address:
        if "/" in args.address:  # If Address has subnet mask symbol(/), eg: 192.168.1.0/30
            try: 
                network = ipaddress.IPv4Network(args.address, strict=False)  # validate if it's a CIDR network

                totalAddress = 0
                max_threads = 1024  # Set maximum number of threads to 10
                ip_list = []

                for ip in network:
                    ip_list.append(str(ip))
                    totalAddress += 1

                def ping_test_wrapper(ip_address):
                    ping_test(ip_address, ping_count)

                with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                    executor.map(ping_test_wrapper, ip_list)
            except ValueError as e:
                print(f"Invalid CIDR address: {e}")
        else:  # Single IP address or hostname, instead of IP range
            totalAddress += 1
            ping_test(args.address,ping_count)

    time_elapsed = time.time() - start_time            #calculate elapsed time
    print("-------------------------------------------------------------------------------------")
    print("{0:55} Time elapsed:{1:>8.2f} seconds\n".format("Number of total addresses: "+str(totalAddress),time_elapsed))
    alive_sorted = sorted(alive, key=ipsorter)
    print(color.BOLD+color.UNDERLINE+"Alive:"+color.END+" [{}]\n {} ".format(len(alive),(", ").join(alive_sorted)))
    dead_sorted = sorted(dead, key=ipsorter)
    print(color.BOLD+color.UNDERLINE+"Dead:"+color.END+" [{}]\n {}".format(len(dead),(", ").join(dead_sorted)))
    unknown_sorted = sorted(unknown, key=ipsorter)
    print(color.BOLD+color.UNDERLINE+"Unknown:"+color.END+" [{}]\n {}".format(len(unknown),(", ").join(unknown_sorted)))
    
    if args.write:                      #-w argument, export output as txt
        with open('%s-Alive.txt' % date, 'w') as f:
            for item in alive_sorted:
                f.write("%s\n" % item)
        with open('%s-Alive_RTT.txt' % date, 'w') as f:
            for item in alive_avg:
                f.write("%s\n" % item)
        with open('%s-Dead.txt' % date, 'w') as f:
            for item in dead_sorted:
                f.write("%s\n" % item)
        print("\nCheck output files for complete results!")

if __name__ == "__main__":
    main()
