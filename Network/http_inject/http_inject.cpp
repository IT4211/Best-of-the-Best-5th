#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "pcap.h"
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <windows.h>
#include <process.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <IPHlpApi.h>

#define ETH_HDRLEN 14      // Ethernet header length
#define IP_HDRLEN 20	   // IP header length
#define TCP_HDRLEN 20	   // TCP header length

#define ETHER_ADDR_LEN 6

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806


typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

typedef struct ether_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}ETHER_HDR;

typedef struct ip_header {
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	u_short crc;
	struct in_addr saddr;
	struct in_addr daddr;
}IP_HDR;

typedef struct tcp_header {
	unsigned short sport;
	unsigned short dport;
	unsigned int sequence;
	unsigned int acknowledge;
	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;
	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;
	unsigned char ecn : 1;
	unsigned char cwr : 1;
	unsigned short window;
	unsigned short crc;
	unsigned short urgent_pointer;
}TCP_HDR;

typedef struct pseudo_header {
	in_addr source_address;
	in_addr dest_address;
	u_char placeholder;
	u_char protocol;
	u_short tcp_length;
}PS_HDR;

u_short ip_sum_calc(u_short len_ip_header, u_short * buffer)
{
	u_short word16;
	u_int sum = 0;
	u_short i;

	for (i = 0; i < len_ip_header; i = i + 2)
	{
		word16 = ((buffer[i] << 8) & 0xFF00) + (buffer[i + 1] & 0xFF);
		sum = sum + (u_int)word16;
	}
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	sum = ~sum;

	return ((u_short)sum);
}

unsigned short checksum(unsigned short *buf, int len)
{
	register unsigned long sum = 0;
	unsigned short result;

	while (len--)
		sum += *buf++;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	result = 0xffff & (~sum);

	return result;
}

int main()
{
	pcap_t* pkt;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	pcap_if_t *dev;

	int res;
	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &dev, errbuf) == -1) {
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	printf("%s\n", dev->name);

	if ((pkt = pcap_open(dev->name,	65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
		pcap_freealldevs(dev);
		return -1;
	}

	printf("\nlistening on %s...\n", dev->description);

	while ((res = pcap_next_ex(pkt, &pkt_header, &pkt_data)) >= 0) {
		if (res == 0)
			continue;
		int tpl;
		int ip_size;
		int tcp_size;
		int payload_size;
		int seq;
		ETHER_HDR* ether_h;
		PS_HDR* ps_h;
		IP_HDR* ip_h;
		TCP_HDR* tcp_h;
		u_char *payload;
		const char *forward = "blocked!";
		const int forward_len = strlen(forward);
		u_char forward_fin_packet[ETH_HDRLEN + IP_HDRLEN + TCP_HDRLEN + 8];

		ps_h = (PS_HDR*)malloc(sizeof(PS_HDR));

		ether_h = (ETHER_HDR*)(pkt_data);
		if (ntohs(ether_h->ether_type) != ETHERTYPE_IP) {
			continue;
		}
		// ethernet header copy 
		memcpy(forward_fin_packet, ether_h, sizeof(ETHER_HDR));

		ip_h = (IP_HDR*)(pkt_data + ETH_HDRLEN);
		if (ip_h->proto != 0x06) {
			continue;
		}
		tpl = ip_h->tlen;
		ip_h->tlen = htons(sizeof(forward_fin_packet) - ETH_HDRLEN);
		ip_size = (ip_h->ver_ihl & 0xf) * 4;
		ip_h->crc = 0;

		u_short ipdata[20];
		char *ptr;
		ptr = (char*)ip_h;
		for (int i = 0; i < 20; i++) {
			ipdata[i] = *(unsigned char*)ptr++;
		}		
		ip_h->crc = htons(ip_sum_calc(ip_size, ipdata));	// ip header checksum 
		
		// ip header copy
		memcpy(forward_fin_packet + sizeof(ETHER_HDR), ip_h, sizeof(IP_HDR));

		/* build pseudo header */
		memcpy(&ps_h->source_address, &ip_h->saddr, sizeof(ps_h->source_address)); 
		memcpy(&ps_h->dest_address, &ip_h->daddr, sizeof(ps_h->dest_address));
		ps_h->placeholder = 0;
		ps_h->protocol = 6;
		ps_h->tcp_length = htons(sizeof(TCP_HDR) + strlen(forward));

		tcp_h = (TCP_HDR*)(pkt_data + ETH_HDRLEN + ip_size);

		if (ntohs(tcp_h->dport) != 80) {
			continue;
		}
		
		tcp_size = tcp_h->data_offset * 4;

		seq = ntohl(tcp_h->sequence);
		seq += (pkt_header->len) - ETH_HDRLEN - IP_HDRLEN - TCP_HDRLEN;

		tcp_h->sequence = htonl(seq);
		tcp_h->fin = 1;
		tcp_h->syn = 0;
		tcp_h->rst = 0;
		tcp_h->psh = 0;
		tcp_h->ack = 1;
		tcp_h->urg = 0;

		tcp_h->crc = 0;

		u_char *pseudo;
		u_int tcp_data_size;
		tcp_data_size = sizeof(PS_HDR) + sizeof(TCP_HDR) + strlen(forward);
		pseudo = (u_char*)malloc(tcp_data_size);
		memcpy(pseudo, ps_h, sizeof(PS_HDR));
		memcpy(pseudo + sizeof(PS_HDR), tcp_h, sizeof(TCP_HDR));
		memcpy(pseudo + sizeof(PS_HDR) + sizeof(TCP_HDR), forward, strlen(forward));

		tcp_h->crc = checksum((u_short*)pseudo, tcp_data_size/2);	// tcp header checksum
		printf("my check sum : %x, %x\n", tcp_h->crc, htons(tcp_h->crc));

		// tcp header copy
		memcpy(forward_fin_packet + sizeof(ETHER_HDR) + sizeof(IP_HDR), tcp_h, sizeof(TCP_HDR));

		payload = (u_char*)(pkt_data + ETH_HDRLEN + ip_size + tcp_size);
		payload_size = tpl - (ETH_HDRLEN + ip_size + tcp_size);

		if (strncmp((const char*)payload, "GET ", 4) != 0) {
			continue;
		}
		printf("Yes!! catch HTTP GET\n");

		memcpy(forward_fin_packet + sizeof(ETHER_HDR) + sizeof(IP_HDR) + sizeof(TCP_HDR), forward, strlen(forward));

		if (pcap_sendpacket(pkt, forward_fin_packet, sizeof(forward_fin_packet)) == 0)
			printf("OK! http inject clear!!!\n");
			
	}
	return 0;
}