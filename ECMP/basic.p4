/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//constants defined, 16 bits(like short)
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_QUERY = 0x0801;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
//define alias for bit<n>
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

//define a register persistent through all packets
register<bit<32> >(3) reg_pkt_count;

//headers defined
//ethernet is usually the first header, all important
//length should not be changed(protocol)
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/*
 * This is a custom protocol header for the query packet. We'll use
 * ethertype 0x0801 for is (see parser)
 */
header query_t {
    bit<32>  pkt_count_1;
    bit<32>  pkt_count_2;
    bit<32>  pkt_count_total;
    bit<16>  protocol;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl; //important, time to live
    bit<8>    protocol; //important
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr; //important
    ip4Addr_t dstAddr; //important
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

//local variable, whose life span is a single packet
struct metadata {
    /* empty, but there already exists predefined vaiables with critical functionalities
	e.g. changing standard_metadata.egress_spec will change packet egress port*/
    bit<14> ecmp_select;
    //to read packet counts through path 1 so far
    bit<32> pkt_count_1;
    //to read packet counts through path 2 so far
    bit<32> pkt_count_2;
    //to read total packet counts so far
    bit<32> pkt_count_total;
}

//header stack, add all the headers you plan to use
struct headers {
    ethernet_t   ethernet;
    query_t      query;
    ipv4_t       ipv4;
    tcp_t        tcp;   
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
//parser logic
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        /* TODO: add parser logic */
        transition parse_ethernet; //always transfer to parse_ethernet state
    }

    state parse_ethernet{
	//try to parse and match the format of ethernet header
        packet.extract(hdr.ethernet);
        //switch case
        transition select(hdr.ethernet.etherType) //get next header type(e.g. ipv4, ipv6)
        {
            TYPE_QUERY: parse_query;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_query{
        packet.extract(hdr.query);
        transition select(hdr.query.protocol) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
     }

    //only when packet passes this state(triggered extract), ipv4 header becomes valid
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
     }

     state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
//pass
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_ecmp_select(bit<16> ecmp_base, bit<32> ecmp_count) {
        /* TODO: hash on 5 tuples and save the hash result in meta.ecmp_select
           so that the ecmp_nhop table can use it to make a forwarding decision accordingly */
        //generate hash value between ecmp_base to ecmp_count
        hash(meta.ecmp_select, HashAlgorithm.crc16, ecmp_base,
        {
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            hdr.ipv4.protocol,
            hdr.tcp.srcPort,
            hdr.tcp.dstPort
        },
        ecmp_count);

        //read packet counts so far into local variables
        //if-statement in actions unsupported on register read/write 
        reg_pkt_count.read(meta.pkt_count_1, 0);
        reg_pkt_count.read(meta.pkt_count_2, 1);
        reg_pkt_count.read(meta.pkt_count_total, 2);

        //only monitor load balancer s1
        if(ecmp_count != 1)
        {               
            //For query packet, retrieve packet counts in register as header field value
            if(hdr.query.isValid())
            {
                hdr.query.pkt_count_1 = meta.pkt_count_1;
                hdr.query.pkt_count_2 = meta.pkt_count_2;
                hdr.query.pkt_count_total = meta.pkt_count_total;
            }
            else //For normal packet, reocrd the number of bytes
            {
                //packet through path 1
                if(meta.ecmp_select == 0)
                {
                    meta.pkt_count_1 = meta.pkt_count_1 + standard_metadata.packet_length;
                    meta.pkt_count_total = meta.pkt_count_total + standard_metadata.packet_length;               
                }
                else if(meta.ecmp_select == 1) //packet through path 2
                {
                    meta.pkt_count_2 = meta.pkt_count_2 + standard_metadata.packet_length;
                    meta.pkt_count_total = meta.pkt_count_total + standard_metadata.packet_length;
                }              
            }
        }  
        //update packet counts to register
        reg_pkt_count.write(0, meta.pkt_count_1);
        reg_pkt_count.write(1, meta.pkt_count_2);
        reg_pkt_count.write(2, meta.pkt_count_total);     
    }

    action set_nhop(macAddr_t nhop_dmac, ip4Addr_t nhop_ipv4, egressSpec_t port) {
        //decide which port of current switch to go to
        standard_metadata.egress_spec = port;
        //previous destination(switch) is now our source
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        //new destination address
        hdr.ethernet.dstAddr = nhop_dmac;
        hdr.ipv4.dstAddr = nhop_ipv4;
        //decrement ttl
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    //when incoming packet passes this table, it has diff actions based on its dstAddr
    table ecmp_group {
        key = {
            //longest prefix match
            hdr.ipv4.dstAddr: lpm;
        }
        //switch case based on key
        actions = {
            drop;
            set_ecmp_select;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            drop;
            set_nhop;
        }
        size = 2;
    }

    //ingress logic starts here
    apply {
         /* TODO: apply ecmp_group table and ecmp_nhop table if IPv4 header is
         * valid and TTL hasn't reached zero
         */
        if(hdr.ipv4.isValid() && hdr.ipv4.ttl > 0){
            ecmp_group.apply();
            ecmp_nhop.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
//pass
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
//pass
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
//reassemble our packet
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* TODO: add deparser logic */
        //order matters
        packet.emit(hdr.ethernet);
        packet.emit(hdr.query);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
