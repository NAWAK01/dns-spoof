"""
Ehternet Packet Header

struct ethhdr {
    unsigned char h_dest[ETH_ALEN];   /* destination eth addr */
    unsigned char h_source[ETH_ALEN]; /* source ether addr    */
    __be16        h_proto;            /* packet type ID field */
} __attribute__((packed));

ARP Packet Header

struct arphdr {
    uint16_t htype;    /* Hardware Type           */
    uint16_t ptype;    /* Protocol Type           */
    u_char   hlen;     /* Hardware Address Length */
    u_char   plen;     /* Protocol Address Length */
    uint16_t opcode;   /* Operation Code          */
    u_char   sha[6];   /* Sender hardware address */
    u_char   spa[4];   /* Sender IP address       */
    u_char   tha[6];   /* Target hardware address */
    u_char   tpa[4];   /* Target IP address       */
};
"""

import socket
import struct
import binascii

rawSocket = socket.socket(socket.AF_PACKET,
                          socket.SOCK_RAW,
                          socket.htons(0x0003))

while True:

    packet = rawSocket.recvfrom(2048)
    ethhdr = packet[0][0:14]
    eth = struct.unpack("!6s6s2s", ethhdr)

    arphdr = packet[0][14:42]
    arp = struct.unpack("2s2s1s1s2s6s4s6s4s", arphdr)
    # skip non-ARP packets
    ethtype = eth[2]
    if ethtype != '\x08\x06': continue

    print("-------------- ETHERNET_FRAME -------------")
    print("Dest MAC:        ", binascii.hexlify(eth[0]))
    print("Source MAC:      ", binascii.hexlify(eth[1]))
    print("Type:            ", binascii.hexlify(ethtype))
    print("--------------- ARP_HEADER ----------------")
    print("Hardware type:   ", binascii.hexlify(arp[0]))
    print("Protocol type:   ", binascii.hexlify(arp[1]))
    print("Hardware size:   ", binascii.hexlify(arp[2]))
    print("Protocol size:   ", binascii.hexlify(arp[3]))
    print("Opcode:          ", binascii.hexlify(arp[4]))
    print("Source MAC:      ", binascii.hexlify(arp[5]))
    print("Source IP:       ", socket.inet_ntoa(arp[6]))
    print("Dest MAC:        ", binascii.hexlify(arp[7]))
    print("Dest IP:         ", socket.inet_ntoa(arp[8]))
    print("-------------------------------------------")