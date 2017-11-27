from scapy.all import *
import sys

InterFace = sys.argv[1]

def cb(pkt):
    print "ok"



sniff(iface=InterFace, prn=cb)
