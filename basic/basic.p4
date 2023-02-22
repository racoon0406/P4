/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//constants defined, 16 bits(like short)
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
//define alias for bit<n>
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

//headers defined
//ethernet is usually the first header, all important
//length should not be changed(protocol)
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

//ipv4 is usually the second header
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

//local variable, whose life span is a single packet
struct metadata {
    /* empty, but there already exists predefined vaiables with critical functionalities
	e.g. changing standard_metadata.egress_spec will change packet egress port*/
}

//header stack, add all the headers you plan to use
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
//  ipv4_t       inner_ipv4; //legal to have same type
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
		TYPE_IPV4: parse_ipv4;
		default: accept;
	}
	//transition parse_ipv4;//transfer to ipv4 header
    }
    //only when packet passes this state(triggered extract), ipv4 header becomes valid
    state parse_ipv4{
	packet.extract(hdr.ipv4);
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

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        /* TODO: fill out code in action body */
	//decide which port of current switch to go to
	standard_metadata.egress_spec = port;
	//previous destination(switch) is now our source
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	//new destination address
	hdr.ethernet.dstAddr = dstAddr;
	//decrement ttl
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    //when incoming packet passes this table, it has diff actions based on its dstAddr
    table ipv4_lpm {
        key = {
            //longest prefix match
            hdr.ipv4.dstAddr: lpm;
        }
	//switch case based on key
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    //ingress logic starts here
    apply {
        /* TODO: fix ingress control logic
         *  - ipv4_lpm(table) should be applied only when IPv4 header is valid
         */
	if(hdr.ipv4.isValid()){
		ipv4_lpm.apply();
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
	packet.emit(hdr.ipv4);
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
