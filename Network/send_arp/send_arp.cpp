#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#include "pcap.h"
#include <stdio.h>
#include <tchar.h>
#include <stdlib.h>
#include <windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <IPHlpApi.h>

#define ETH_HDRLEN 14      // Ethernet header length
#define ARP_HDRLEN 28      // ARP header length

#define ARPHRD_ETHER 1
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ETHER_ADDR_LEN 6

typedef struct mac_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;

typedef struct ether_header {
	unsigned char ether_dhost[ETHER_ADDR_LEN];
	unsigned char ether_shost[ETHER_ADDR_LEN];
	unsigned short ether_type;
}ETHER_HDR;

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct arp_header {
	u_int16_t htype;
	u_int16_t ptype;
	u_int8_t hlen;
	u_int8_t plen;
	u_int16_t opcode;
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
	u_int8_t target_ip[4];
}ARP_HDR;

typedef struct ip_header {
	u_char ver_ihl;
	u_char tos;
	u_short tlen; 
	u_short identification; 
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	u_short crc;
	ip_address saddr;    
	ip_address daddr;
	u_int op_pad; 
}IP_HDR;



int main(int argc, char *argv[])
{
	pcap_t* pkt;
	//struct pcap_pkthdr *pkt_header;
	//const u_char *pkt_data;
	pcap_if_t *dev;
	//char *dev;	
	char errbuf[PCAP_ERRBUF_SIZE];
	const char* target_ip = argv[1];

	// Local IP Address, Local MAC Address, Gateway�� ���´�.  
	char *Myip = (char*)malloc(16);
	char *Gateway = (char*)malloc(16);
	char *Mymac = (char*)malloc(17);
	u_int8_t byteMAC[8];
	unsigned int lntMyip;

	PIP_ADAPTER_INFO AdapterInfo;	// ��Ͱ� ������ �ִ� ������ ����
	PIP_ADAPTER_INFO pAdapter = NULL;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	DWORD dwRetVal = 0;

	/*
	if (argc < 2) {
		fprintf(stderr, "Usage : send_arp <victim ip>\n");
		return -1;
	}*/
	

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));

	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}

	if (GetAdaptersInfo(AdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(AdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = AdapterInfo;
	}

	sprintf(Myip, "%s", pAdapter->IpAddressList.IpAddress.String);
	sprintf(Gateway, "%s", pAdapter->GatewayList.IpAddress.String);
	sprintf(Mymac, "%02X:%02X:%02X:%02X:%02X:%02X",
		AdapterInfo->Address[0], AdapterInfo->Address[1],
		AdapterInfo->Address[2], AdapterInfo->Address[3],
		AdapterInfo->Address[4], AdapterInfo->Address[5]);
	memcpy(byteMAC, AdapterInfo->Address, sizeof(byteMAC));

	printf("IP address: \t%s\n", Myip);
	printf("Gateway: \t%s\n", Gateway);
	printf("MAC: \t%s\n", Mymac);
	free(AdapterInfo);

	lntMyip = (unsigned int)inet_addr(Myip);

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &dev, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	printf("%s\n", dev->name);

	if ((pkt = pcap_open(dev->name,          // name of the device
		65536,            // portion of the packet to capture
						  // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
		/* Free the device list */
		pcap_freealldevs(dev);
		return -1;
	}

	printf("\nlistening on %s...\n", dev->description);

	u_char packet[ETH_HDRLEN + ARP_HDRLEN + 60];

	ETHER_HDR *ether = (ETHER_HDR*)packet;
	memset(ether->ether_dhost, 0xFF, sizeof(ether->ether_dhost));
	memcpy(ether->ether_shost, byteMAC, sizeof(ether->ether_shost));
	ether->ether_type = htons(ETHERTYPE_ARP);

	ARP_HDR *arp = (ARP_HDR*)(packet + ETH_HDRLEN);
	arp->htype = htons(ARPHRD_ETHER);
	arp->ptype = htons(ETHERTYPE_IP);
	arp->hlen = sizeof(mac);
	arp->plen = sizeof(ip_address);
	arp->opcode = htons(ARP_OP_REQUEST);
	memcpy(arp->sender_mac, byteMAC, sizeof(arp->sender_mac));
	*(unsigned int*)(arp->sender_ip) = lntMyip;
	memset(arp->target_mac, 0x00, sizeof(arp->target_mac));
	*(unsigned int*)(arp->target_ip) = (unsigned int)inet_addr(target_ip);
	
	while (1) {
		if (pcap_sendpacket(pkt, packet, sizeof(packet)) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pkt));
			return -1;
		}
		printf("send packet!!\n");
		Sleep(1000);
	}
	pcap_freealldevs(dev);

	free(Myip);
	free(Gateway);
	free(Mymac);

	return 0;
}