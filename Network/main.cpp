#include <stdio.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

int main(void)
{
    pcap_t *handle;
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 mask;
    bpf_u_int32 net;

    struct ether_header *ether_h;
    struct iphdr *ip_h;
    struct tcphdr *tcp_h;

    dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
    }


    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){             // find the IPv4 network number and netmask for a device
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);           // open a device for capturing
    if(handle == NULL){
        fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
        return(2);
    }

    int count = 0;

    while(1){
        if(pcap_next_ex(handle, &pkt_header, &pkt_data) < 0){         // read the next packet from a pcap_t, error control!
            printf("Can't read packet\n");
            break;
        }

        printf("\n===== packet count : %d =====\n", count++);

        printf("packet len : %d\n", pkt_header->len);

        /* ethernet header */
        ether_h = (ether_header*)pkt_data;

        printf("src_mac : %s\n", ether_ntoa((ether_addr*)&(ether_h->ether_shost)));  // type casting : ether_addr
        printf("dst_mac : %s\n", ether_ntoa((ether_addr*)&(ether_h->ether_dhost)));

        if(ether_h->ether_type != 0x0008){
            printf("this packet is not IPv4\n");
            continue;
        }

        /* ip header */
        ip_h = (iphdr*)(pkt_data + sizeof(ether_header));

        printf("src_ip_addr : %s\n", inet_ntoa(*((in_addr*)&(ip_h->saddr))));
        printf("dst_ip_addr : %s\n", inet_ntoa(*((in_addr*)&(ip_h->daddr))));

        if(ip_h->protocol != 6){
            printf("this packet is not TCP\n");
            continue;
        }

        /* tcp header */
        tcp_h = (tcphdr*)(pkt_data + sizeof(ether_header) + ip_h->ihl * 4);

        printf("src_port : %d\n", ntohs(*((unsigned short*)&(tcp_h->th_sport)))); // type casting
        printf("dst_port : %d\n", ntohs(*((unsigned short*)&(tcp_h->th_dport))));

    }

    pcap_close(handle);
    return 0;
}
