from scapy.all import *
import sys

if len(sys.argv) != 2:
    print "usage: python tcp_block.py interface"
    sys.exit(0)

InterFace = sys.argv[1]

MyMac = get_if_hwaddr(InterFace)

HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

def cb(pkt):
    if Ether in pkt and IP in pkt and TCP in pkt:
        if pkt[TCP].flags & RST or pkt[TCP].flags & FIN:
            return
        mypkt = pkt[Ether]/pkt[IP]/pkt[TCP]
        mypkt[TCP].remove_payload()
        del mypkt[IP].chksum
        del mypkt[TCP].chksum
	mypkt[Ether].src = MyMac

        try:
            payload_len = len(pkt[TCP].Raw)
        except:
            payload_len = 1
        
	mypkt[TCP].seq += payload_len
        mypkt[TCP].flags = RST | ACK
        sendp(mypkt, iface=InterFace)

        if "HTTP" in str(pkt) and pkt[TCP].load.split()[0] in HTTP_METHODS:
            print "HTTP"
            mypkt[TCP].flags = FIN | ACK
            mypkt = mypkt / "blocked\r\n"


        mypkt[Ether].dst, mypkt[Ether].src = pkt[Ether].src, MyMac
        mypkt[IP].src, mypkt[IP].dst = pkt[IP].dst, pkt[IP].src
        mypkt[TCP].seq, mypkt[TCP].ack = pkt[TCP].ack, pkt[TCP].seq + payload_len
        sendp(mypkt, iface=InterFace)

def main():
    sniff(iface=InterFace, prn=cb)

main()
