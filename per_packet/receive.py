#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR
from query_h import Query, Index

#list to collect packet index
packet_sequence = list()

def count_inversion(sequence):
    maxV = -1
    count = 0
    for i in range(len(sequence) - 1):
        maxV = max(maxV, sequence[i])
        if(maxV > sequence[i + 1]):
            count += 1
    return count

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]
def handle_pkt(pkt):
    # look for global var instead of creating a local var
    global packet_sequence
    if Query in pkt:        
        print("got a query packet")
        pkt.show2()
        sys.stdout.flush()
        print("packet received sequence: ", packet_sequence)
        num_inversion = count_inversion(packet_sequence)
        print("number of inversions: ", num_inversion)
    elif TCP in pkt and pkt[TCP].dport == 1234:
        print("got a normal packet")       
        packet_sequence.append(pkt[Index].pkt_index)
        # print("pkt_index: ", pkt[Index].pkt_index)
        pkt.show2()
        sys.stdout.flush()
    

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
