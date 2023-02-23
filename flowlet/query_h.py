import sys

from scapy.all import (
    IP, TCP, Ether, 
    Packet, bind_layers, IntField, ShortField
    )

TYPE_IPV4 = 0x0800
#normal packet
TYPE_INDEX = 0x0802
#query packet
TYPE_QUERY = 0x0801


class Query(Packet):
    name = "Query"
    fields_desc=[ 
                IntField("pkt_count_1", 0),    	
                IntField("pkt_count_2", 0),    	
                IntField("pkt_count_total", 0),    	    
                ShortField("protocol", 0)]
#When Scapy encounters an Ethernet type=0x0801, it will parse the next layer as "Query" header
bind_layers(Ether, Query, type = TYPE_QUERY)
bind_layers(Query, IP, protocol = TYPE_IPV4)

class Index(Packet):
    name = "Index"
    fields_desc=[ 
                IntField("pkt_index", 0),    	   	    
                ShortField("protocol", 0)]
#When Scapy encounters an Ethernet type=0x0802, it will parse the next layer as "Index" header
bind_layers(Ether, Index, type = TYPE_INDEX)
bind_layers(Index, IP, protocol = TYPE_IPV4)