#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ARP_H_SIZE sizeof(struct ether_arp)

int main(int argc, char *argv[]){
	pcap_t* pkt;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	bpf_u_int32 mask;
	bpf_u_int32 net;

	struct ether_header ether_h;
	struct ether_arp arp_h;
	arp_h.arp_hrd = htons(ARPHRD_ETHER);
	arp_h.arp_pro = htons(ETH_P_IP);
	arp_h.arp_hln = ETHER_ADDR_LEN;
	arp_h.arp_pln = sizeof(in_addr_t);
	arp_h.arp_op = htons(ARPOP_REQUEST);


	struct sockaddr_in *local_ip;
	const unsigned char *local_mac;
	const char *target_ip = argv[1];

	if(argc < 2){
		fprintf(stderr, "Usage : send_arp <victim ip>\n");
		return -1;
	}

	dev = pcap_lookupdev(errbuf);
	if(dev == NULL){
		fprintf(stderr, "pcap_lookupdev error : %s\n", errbuf);
		return -1;
	}

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
		fprintf(stderr, "pcap_lookupnet error : %s\n", errbuf);
		net = 0;
		mask = 0;
	}

	pkt = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(pkt == NULL){
		fprintf(stderr, "pcap_open_live error : %s\n", errbuf);
		return -1;
	}

	/* get local ip & mac address */
	/* frame struct */
	// frame = | ethernet | arp | 

	int s;
	struct ifreq ifr;
	char *iface = dev;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	ioctl(s, SIOCGIFADDR, &ifr);
	local_ip = (struct sockaddr_in*)&ifr.ifr_addr;
	
	ioctl(s, SIOCGIFHWADDR, &ifr);
	local_mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;

	close(s);

	ether_h.ether_type = htons(ETH_P_ARP);												// ether_h type set
	memset(ether_h.ether_dhost, 0xff, sizeof(ether_h.ether_dhost)); 					// ether_h dst mac set
	memcpy(ether_h.ether_shost, local_mac, sizeof(ether_h.ether_shost));				// ether_h src mac set
	memcpy(&arp_h.arp_spa, &source_ip_addr->sin_addr.s_addr, sizeof(arp_h.arp_spa));	// arp_h src ip set
	memcpy(&arp_h.arp_sha, local_mac, sizeof(arp_h.arp_sha));							// arp_h src mac set
	
	struct in_addr target_ip_addr = {0};
    if(!inet_aton(target_ip, &target_ip_addr)){
        fprintf(stderr, "%s is not a valid IP address", target_ip);
        exit(1);
    }
    memcpy(&arp_h.arp_tpa, &target_ip_addr.s_addr, sizeof(arp_h.arp_tpa));			// arp_h target ip set

    // get target mac address 
    //memcpy(&arp_h.arp_tha, 0x00, sizeof(arp_h.arp_tha));							// arp_h target mac set : 0x00
    memset(&arp_h.arp_tha, 0, sizeof(arp_h.arp_tha));

	/* get local ip and mac test */
	printf("test : %s , %s\n", local_ip, local_mac);

	unsigned char frame[ETHER_HDR_LEN + ARP_H_SIZE];
    memcpy(frame, &ether_h, sizeof(ETHER_HDR_LEN));
    memcpy(frame + sizeof(ETHER_HDR_LEN), &arp_h, sizeof(ARP_H_SIZE));

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

}
