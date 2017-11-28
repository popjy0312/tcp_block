from scapy.all import *
import sys
import logging as log

if len(sys.argv) != 2:
    print "usage: python tcp_block.py interface"
    sys.exit(0)

log.basicConfig(level = log.DEBUG)

InterFace = sys.argv[1]

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10

def cb(pkt):
    if Ether in pkt and IP in pkt and TCP in pkt:
        #pkt[TCP].show()
        if pkt[TCP].flags & RST:
            return
        mypkt = pkt[Ether]/pkt[IP]/pkt[TCP]
        mypkt[TCP].remove_payload()
        del mypkt[IP].chksum
        del mypkt[TCP].chksum

        log.debug("original packet seq is %d" % pkt[TCP].seq)
        log.debug("original packet ack is %d" % pkt[TCP].ack)
        mypkt[TCP].seq += 1
        #pkt[TCP].ack += 1
        mypkt[TCP].flags = RST | ACK
        log.debug(" forward packet seq is %d" % mypkt[TCP].seq)
        log.debug(" forward packet ack is %d" % mypkt[TCP].ack)
        sendp(mypkt, iface=InterFace)


        if "HTTP" in pkt and pkt[TCP].Raw[:4] == 'HTTP':
            print "HTTP"
            mypkt[TCP].flags = FIN | ACK
            mypkt = mypkt / "blocked"

        try:
            Raw = pkt[TCP].Raw
        except:
            Raw = ""
        payload_len = len(Raw)
        if payload_len == 0:
            payload_len += 1
        mypkt[Ether].dst, mypkt[Ether].src = pkt[Ether].src, pkt[Ether].dst
        mypkt[IP].src, mypkt[IP].dst = pkt[IP].dst, pkt[IP].src
        mypkt[TCP].seq, mypkt[TCP].ack = pkt[TCP].ack, pkt[TCP].seq + payload_len
        log.debug("backward packet seq is %d" % mypkt[TCP].seq)
        log.debug("backward packet ack is %d" % mypkt[TCP].ack)
        sendp(mypkt, iface=InterFace)

def main():
    sniff(iface=InterFace, prn=cb)

main()
