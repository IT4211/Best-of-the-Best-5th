#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

#define ARP_H_SIZE sizeof(struct ether_arp)

// get local ip addr and mac addr
void get_ifconfig(char * dev, char *ip, char *mac){
    int s;
    struct ifreq ifr;
    char *iface = dev;

    s = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

    ioctl(s, SIOCGIFADDR, &ifr); // ip address
    inet_ntop(AF_INET, &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), ip, INET_ADDRSTRLEN);

    ioctl(s, SIOCGIFHWADDR, &ifr); // mac address
    mac = ether_ntoa((struct ether_addr*)ifr.ifr_hwaddr.sa_data);

    close(s);

    printf("[in function] ip : %s \n", ip);
    printf("[in function] mac : %s \n", mac);
}

int main(int argc, char *argv[])
{
    pcap_t* pkt;
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    //struct in_addr net_addr;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    char *local_ip;
    char *local_mac;
    const char* target_ip = argv[1];

    if(argc < 2){
        fprintf(stderr, "Usage : send_arp <victim ip>\n");
        return -1;
    }

    struct ether_header *ether_h;
    ether_h->ether_type = htons(ETH_P_ARP); // 0x0806, ARP packet

    struct ether_arp arp_req;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find defult deavice : %s\n", errbuf);
        return(2);
    }

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    get_ifconfig(dev, local_ip, local_mac);

    printf("%s \n", local_ip);
    printf("%s \n", local_mac);

    /* set victim ip/mac */

    // get victim ip address

    struct in_addr target_ip_addr = {0};
    if(!inet_aton(target_ip, &target_ip_addr)){
        fprintf(stderr, "%s is not a valid IP address", target_ip);
        exit(1);
    }
    memcpy(&arp_req.arp_tpa, &target_ip_addr.s_addr, sizeof(arp_req.arp_tpa));


    // get victim mac address
    pkt = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(pkt == NULL){
        fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
        return(2);
    }

    memset(ether_h->ether_dhost, "0xff", sizeof(ether_h->ether_dhost));
    //ether_h->ether_dhost.ether_addr_octet[] = ether_aton(host.ether_addr_octet);

    unsigned char frame[ETHER_HDR_LEN + ARP_H_SIZE];
    memcpy(frame, &ether_h, sizeof(ETHER_HDR_LEN));
    memcpy(frame+sizeof(ETHER_HDR_LEN), &arp_req, sizeof(ARP_H_SIZE));

    if(pcap_sendpacket(pkt, frame, sizeof(frame)) == -1){
        pcap_perror(pkt, 0);
        pcap_close(pkt);
        exit(1);
    }

    while(1){
        if(pcap_next_ex(pkt, &pkt_header, &pkt_data) < 0){
            printf("Can't read packet\n");
            break;
        }
    }


    /* Make frame : | ethernet | arp | */
    /* send frame, using sendpacket */

    if(pcap_sendpacket(pkt, frame, sizeof(frame)) == -1){
        pcap_perror(pkt, 0);
        pcap_close(pkt);
        exit(1);
    }

    pcap_close(pkt);
    return 0;
}

