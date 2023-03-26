import sys

from scapy.all import (
    IP, TCP, Ether, 
    Packet, bind_layers, IntField, ShortField
    )

#normal packet
TYPE_IPV4 = 0x0800
#query packet
TYPE_QUERY = 0x0801

class Query(Packet):
    name = "query"
    fields_desc=[ 
                IntField("pkt_count_1", 0),    	
                IntField("pkt_count_2", 0),    	
                IntField("pkt_count_total", 0),    	    
                ShortField("protocol", 0)]
#When Scapy encounters an Ethernet type=0x0801, it will parse the next layer as "Query" header
bind_layers(Ether, Query, type = TYPE_QUERY)
bind_layers(Query, IP, protocol = TYPE_IPV4)