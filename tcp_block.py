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
    if TCP in pkt:
        #pkt[TCP].show()
        rstpkt = pkt[Ether]/pkt[IP]/pkt[TCP]
        rstpkt[TCP].remove_payload()
        del rstpkt[IP].chksum
        del rstpkt[TCP].chksum
        """
        if rstpkt[TCP].load:
            del rstpkt[TCP].load
            del rstpkt[IP].chksum
            del rstpkt[TCP].chksum
        """
        #rstpkt = pkt.copy()
        log.debug("original packet seq is %d" % pkt[TCP].seq)
        log.debug("original packet ack is %d" % pkt[TCP].ack)
        rstpkt[TCP].seq += 1
        #pkt[TCP].ack += 1
        rstpkt[TCP].flags = RST | ACK
        log.debug(" forward packet seq is %d" % rstpkt[TCP].seq)
        log.debug(" forward packet ack is %d" % rstpkt[TCP].ack)
        sendp(rstpkt, iface=InterFace)

        rstpkt[Ether].dst, rstpkt[Ether].src = rstpkt[Ether].src, rstpkt[Ether].dst
        rstpkt[IP].src, rstpkt[IP].dst = rstpkt[IP].dst, rstpkt[IP].src
        rstpkt[TCP].seq, rstpkt[TCP].ack = rstpkt[TCP].ack, rstpkt[TCP].seq
        log.debug("backward packet seq is %d" % rstpkt[TCP].seq)
        log.debug("backward packet ack is %d" % rstpkt[TCP].ack)
        sendp(rstpkt, iface=InterFace)

def main():
    sniff(iface=InterFace, prn=cb)

main()
