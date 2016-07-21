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

#define ETHER_H_SIZE sizeof(struct ether_header)
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

    printf("%s \n", ip);
    printf("%s \n", mac);
}

// get gateway ip addr
void get_gateway(char *gateway){
    FILE *fp;
    fp = popen("route -n | grep 'UG[ \t]' | awk '{print $2}'","r");
    if(fp != NULL){
        while(fgets(gateway, 1024, fp))
    }
    printf("%s", gateway);
    pclose(fp);
}

int main(int argc, char *argv[])
{
    pcap_t* pkt;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct in_addr net_addr;

    bpf_u_int32 mask;
    bpf_u_int32 net;

    char *local_ip;
    char *local_mac;

    if(argc < 2){
        fprintf(stderr, "Usage : send_arp <victim ip>\n");
        return -1;
    }
    

    struct ether_header *ether_h;
    ether_h->ether_type = htons(ETH_P_ARP); // 0x0806, ARP packet

    struct ether_arp arp_req;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
        fprintf(stderr, "Couldn't find default device : %s\n", errbuf);
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

    // get victim mac address
    // arp_tha = get from origin mac request



    // get victim ip address
    arp_req.arp_tpa = htons(argv[1]);

    /* Make frame : | ethernet | arp | */

    unsigned char frame[ETHER_H_SIZE + ARP_H_SIZE];
    memcpy(frame, &ether_h, ETHER_H_SIZE);
    memcpy(frame + ETHER_H_SIZE, &arp_req, ARP_H_SIZE);

    /* send frame, using sendpacket */
    
    if(pcap_sendpacket(fp, frame, sizeof(frame)) == -1){
        pcap_perror(fp, 0);
        pcap_close(fp);
        exit(1);
    }
    
    pcap_close(pkt);
    return 0;
}
