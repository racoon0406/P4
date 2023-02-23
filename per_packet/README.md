# Implementing per-packet load balancing

## Description
The program performs per-packet load balancing at the first hop(S1), and destination-based forwarding for all other hops (S2-S4). 

By sending query packet, the program can monitor S1 and keep track of the number of bytes sent to each of its outgoing ports. 

To send the data from **h1** to **h4**, please run the following script:
1. 
`xterm h1 h4`
2. In terminal of h4, run:
`./receive.py`
3. In terminal of h1, run:
`./send.py 10.0.4.4 [packet type: 1. Send normal packets 2. Send a query packet] [How many normal packets to send]`
For example: 
`./send.py 10.0.4.4 1 100` will send 100 normal packets with random payload size
`./send.py 10.0.4.4 2 100` will always send 1 query packet

**Note:** Query command `/send.py 10.0.4.4 2 100` will also print the sequence of packets so far and the number of inversions at the destination.