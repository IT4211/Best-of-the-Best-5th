#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap/pcap.h>

#define SIZE_ETHERNET 14
#define SIZE_IP 20
#define SIZE_TCP 20

int main(void)
{
    pcap_t *handle;
    struct pcap_pkthdr *pkt_header;
    const u_char *pkt_data;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    bpf_u_int32 mask;
    bpf_u_int32 net;

    dev = pcap_lookupdev(errbuf);
            if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
            }

    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){             //find the IPv4 network number and netmask for a device
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
        if(pcap_next_ex(handle, &pkt_header, &pkt_data) < 0){         // read the next packet from a pcap_t
            printf("Can't read packet\n");
            break;
        }

        printf("\n===== packet count : %d =====\n", count++);

        printf("packet len : %d\n", pkt_header->len);

        char * dmac = (char*)ether_ntoa((ether_addr *)pkt_data);
        printf("dmac: %s\n", dmac);

        char * smac = (char*)ether_ntoa((ether_addr *)(pkt_data + 6));
        printf("smac: %s\n", smac);

        unsigned short *type = ((unsigned short*)(pkt_data + 12));
        printf("type: %d\n", *type);

        if(*type == 8){     // IPv4
            unsigned char *protocol = ((unsigned char*)(pkt_data + 14 + 9));
            printf("protocol: %d\n", *protocol);

            char *src_ip_addr = inet_ntoa(*(in_addr*)(pkt_data + 26));
            printf("src_ip_addr: %s\n", src_ip_addr);

            char *dst_ip_addr = inet_ntoa(*(in_addr*)(pkt_data + 30));
            printf("dst_ip_addr: %s\n", dst_ip_addr);

            unsigned short src_port = ntohs(*((unsigned short*)(pkt_data + 34)));
            printf("src_port: %d\n", src_port);

            unsigned short dst_port = ntohs(*((unsigned short*)(pkt_data + 36)));
            printf("dst_port: %d\n", dst_port);

        }
        else if(*type == 0xdd86){   // IPv6
            unsigned char *protocol = ((unsigned char*)(pkt_data + 14 + 9));
            printf("protocol: %d\n", *protocol);

            char src_ip6_addr[40];
            inet_ntop(AF_INET6, ((in6_addr*)(pkt_data + 22)), src_ip6_addr, INET6_ADDRSTRLEN);
            printf("****src_ip6_addr: %s\n", src_ip6_addr);

            char dst_ip6_addr[40];
            inet_ntop(AF_INET6, ((in6_addr*)(pkt_data + 22 + 16)), dst_ip6_addr, INET6_ADDRSTRLEN);
            printf("****dst_ip6_addr: %s\n", dst_ip6_addr);
        }
    }
    pcap_close(handle);
    return 0;
}
