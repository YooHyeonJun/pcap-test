#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}
typedef struct {
    char* dev_;
} Param;
Param param = {
    .dev_ = NULL
};
// Ethernet
struct ethernet_hdr {
    u_int8_t ether_dhost[6];
    u_int8_t ether_shost[6];
    u_int16_t ether_type;
} eth;
// IPv4
struct ipv4_hdr {
    u_int8_t ip_ver_ihl;      // version(4), IHL(4)
    u_int8_t ip_proto;        // protocol info
    u_int32_t ip_src;         // src IP
    u_int32_t ip_dst;         // dest IP
} ipv4;
// TCP
struct tcp_hdr {
    u_int16_t th_sport;       // src port
    u_int16_t th_dport;       // dest port
    u_int8_t th_off;          // header size
} tcp;
bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}
void print_payload(const u_char* packet, int ip_offset, int tcp_offset, int payload_len) {
    printf("Payload Data (Hex): ");
    for (int i = 0; i < payload_len && i < 20; i++) {
        printf("%02X ", packet[tcp_offset + i]);
    }
    printf("\n");
}
void print_mac_address(u_int8_t* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
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

        eth.ether_type = 0;
        // Ethernet Header parsing

        // dest mac
        memcpy(eth.ether_dhost, packet, 6);

        // src mac
        memcpy(eth.ether_shost, packet + 6, 6);

        //type
        eth.ether_type = ntohs(*(u_int16_t*)(packet + 12));

        // Ethernet type check (IPv4)
        if (eth.ether_type == 0x0800) {  // IPv4
            // IPv4 header parsing
            int ip_offset = 14;  // Ethernet header length

            // extract IHL
            ipv4.ip_ver_ihl = packet[ip_offset];
            ipv4.ip_proto = packet[ip_offset + 9];  // if tcp then 6
            ipv4.ip_src = *(u_int32_t*)(packet + ip_offset + 12);  // src IP
            ipv4.ip_dst = *(u_int32_t*)(packet + ip_offset + 16);  // dest IP

            if (ipv4.ip_proto == 6) {  // TCP
                // TCP header offset
                int tcp_offset = ip_offset + (ipv4.ip_ver_ihl & 0x0F) * 4;  // TCP 헤더는 IP 헤더 뒤에 위치

                tcp.th_sport = ntohs(*(u_int16_t*)(packet + tcp_offset));  // src port
                tcp.th_dport = ntohs(*(u_int16_t*)(packet + tcp_offset + 2));  // desr port
                tcp.th_off = (packet[tcp_offset + 12] >> 4) * 4;  // TCP header length

                printf("\nEthernet Header:\n");
                printf("Destination MAC: ");
                print_mac_address(eth.ether_dhost);
                printf("\n");

                printf("Source MAC: ");
                print_mac_address(eth.ether_shost);
                printf("\n");

                printf("\nIPv4 Header:\n");
                printf("Source IP: %s\n", inet_ntoa(*(struct in_addr*)&ipv4.ip_src));
                printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&ipv4.ip_dst));

                printf("\nTCP Header:\n");
                printf("Source Port (Converted): %d\n", tcp.th_sport);
                printf("Destination Port (Converted): %d\n", tcp.th_dport);

                // data
                int payload_len = header->caplen - (tcp_offset + tcp.th_off);
                print_payload(packet, ip_offset, tcp_offset, payload_len);
            }
        }
    }

    pcap_close(pcap);
    return 0;
}
