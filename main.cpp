#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/if.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#define PACKET_LENGTH 42

unsigned int len = 0;

typedef struct eth_header {
	uint8_t dhost_mac[6];
	uint8_t shost_mac[6];
	uint16_t type;
} eth_header;

typedef struct arp_header {
	uint16_t hd_type;
	uint16_t proto_type;
	uint8_t hd_size;
	uint8_t proto_size;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
} arp_header;

void usage(){ // print about how to use
	printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
	printf("example: send_arp ens33 192.20.10.5 192.20.10.2\n");	
}

void printMac(u_int8_t *sender_mac, u_int8_t *target_mac){
	printf("--- Final Results ---\n");
	printf("  Sender's Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
	printf("  Target's Mac Address: %02x:%02x:%02x:%02x:%02x:%02x\n", target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
}

void printIp(char *sender_ip, char *target_ip){
	printf("  Sender's IP Address:  %d.%d.%d.%d\n", sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
	printf("  Target's IP Address:  %d.%d.%d.%d\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
	printf("---      END      ---\n");
}

int main(int argc, char *argv[]) {
	if (argc != 4) { // length of argc should be 4
		usage();
		return -1;
	}
	char *interface = argv[1];
	char *sender_ip = argv[2];
	char *target_ip = argv[3];
	char error_buf[256] = {'\0',};

	unsigned char packet[PACKET_LENGTH] = {'\0',};

	eth_header ether;
	arp_header arp;

	struct in_addr iaddr;

	pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 100, error_buf);
	if (handle == NULL) { // if it handles failed, return NULL
		fprintf(stderr, "program couldn't open device %s: %s\n", interface, error_buf);
		return -1;
	}

	memset(packet, 0, PACKET_LENGTH);

	// get sender mac address
	int fd;
	struct ifreq ifr;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFADDR, &ifr);
	struct in_addr my_ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
	ioctl(fd, SIOCGIFHWADDR, &ifr); //mac address

	u_int8_t sender_mac[6];
	u_int8_t target_mac[6];

	memcpy(sender_mac, ifr.ifr_hwaddr.sa_data, 6);
	close(fd);

	// do broad cast
	memset(ether.dhost_mac, 0xff, sizeof(ether.dhost_mac));
	memcpy(ether.shost_mac, sender_mac, 6); // mac address has 6 bytes
	ether.type = htons(0x0806);

	memcpy(packet, &ether, sizeof(ether));
	len += sizeof(ether);

	// struct arp header
	arp.hd_type = htons(0x01);
	arp.proto_type = htons(0x0800);
	arp.hd_size = 6; // length of hardware address size (mac)
	arp.proto_size = 4; // length of protocol address size (ip)
	arp.opcode = htons(0x01);
	memcpy(arp.sender_mac, sender_mac, 0x6);
	memset(arp.target_mac, 0x0, 0x6);
	inet_pton(AF_INET, sender_ip, &iaddr.s_addr);
	memcpy(arp.sender_ip, &iaddr.s_addr, sizeof(arp.sender_ip));
	inet_pton(AF_INET, target_ip, &iaddr.s_addr);
	memcpy(arp.target_ip, &iaddr.s_addr, sizeof(arp.target_ip));

	memcpy(packet + len, &arp, sizeof(arp));
	len += sizeof(arp);

	// arp packet request
	pcap_sendpacket(handle, packet, len);

	// get target mac address
	int if_next_exist = 0;

	while(1){
		struct pcap_pkthdr *header;
		const u_char *recvpacket;
		if_next_exist = pcap_next_ex(handle, &header, &recvpacket);
		if (if_next_exist != 1) continue;
		if (recvpacket[12] == 8 && recvpacket[13] == 6 && recvpacket[20] == 0 && recvpacket[21] == 2) {
			memcpy(target_mac, recvpacket + 22, 6);
			break;
		}
	}

	memset(packet, 0, PACKET_LENGTH);
	len = 0;

	// struct ethernet header
	memcpy(ether.dhost_mac, target_mac, 6);   
	memcpy(ether.shost_mac, sender_mac, 6);
	ether.type = htons(0x0806);

	memcpy(packet, &ether, sizeof(ether));
	len += sizeof(ether);

	// struct arp header
	arp.hd_type = htons(0x01);
	arp.proto_type = htons(0x0800);
	arp.hd_size = 0x06;
	arp.proto_size = 4;
	arp.opcode = htons(0x01);
	memcpy(arp.sender_mac, sender_mac, 6);
	memcpy(arp.target_mac, target_mac, 6);
	inet_pton(AF_INET, sender_ip, &iaddr.s_addr);
	memcpy(arp.sender_ip, &iaddr.s_addr, sizeof(arp.sender_ip));
	inet_pton(AF_INET, target_ip, &iaddr.s_addr);
	memcpy(arp.target_ip, &iaddr.s_addr, sizeof(arp.target_ip));

	memcpy(packet + len, &arp, sizeof(arp));
	len += sizeof(arp);

	// arp packet request
	pcap_sendpacket(handle, packet, len);
	
	printMac(sender_mac, target_mac);
	printIp(sender_ip, target_ip);

	return 0;
}
