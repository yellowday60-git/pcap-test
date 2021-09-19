#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <pcap.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}


typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);


		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        ether_header * eth = (ether_header *) packet;
		if(ntohs(eth->ether_type) != ETHERTYPE_IP) continue;
		ip * ipv4 = (ip *) (packet + ETH_HLEN);
		if(ipv4->ip_p != IPPROTO_TCP) continue;

        //ether 
        printf("=== ETHERNET HEADER ===\n");
        printf("src mac : %02X:%02X:%02X:%02X:%02X:%02X \n",eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        printf("dst mac : %02X:%02X:%02X:%02X:%02X:%02X \n",eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);


        
        //ipv4
        printf("===   IPV4 HEADER   ===\n");
        printf("src IP : %s \n",inet_ntoa(ipv4->ip_src));
        printf("dst IP : %s \n",inet_ntoa(ipv4->ip_dst));

		
		//tcp
		uint32_t IP_HLEN = ipv4->ip_hl * 4;
		tcphdr * tcp = (tcphdr *)(packet + ETH_HLEN + IP_HLEN);

		printf("===   TCP  HEADER   ===\n");
        printf("src port : %d \n",tcp->th_sport);
        printf("dst port : %d \n",tcp->th_dport);

		//payload
		uint32_t TCP_HLEN = tcp->th_off * 4;
		u_char *payload = (u_char *)(packet + ETH_HLEN + IP_HLEN + TCP_HLEN);

		uint32_t packet_len = ntohs(ipv4->ip_len) - IP_HLEN - TCP_HLEN;
		packet_len = (0 >= packet_len ? 0 : packet_len);
		packet_len = (packet_len >= 8 ? 8 : packet_len);

		printf("===  PAYLOAD INFO  ===\n");
		printf("len : %d\n",packet_len);

		if(packet_len > 0){
			printf("payload (8 bytes): ");

			for(int i = 0;  i < packet_len; i++){
				printf("%#X ", payload[i]);
			}
		}
		
		printf("\n\n");

	}

	pcap_close(pcap);
}
