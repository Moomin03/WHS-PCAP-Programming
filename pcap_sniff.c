#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* 패킷을 처리하는 콜백 함수 */
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;
    
    // Ethernet Header 정보 출력
    printf("Ethernet Header: Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, ",
           eth_header->ether_shost[0], eth_header->ether_shost[1], eth_header->ether_shost[2],
           eth_header->ether_shost[3], eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_header->ether_dhost[0], eth_header->ether_dhost[1], eth_header->ether_dhost[2],
           eth_header->ether_dhost[3], eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // IP 패킷인지 확인
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet.\n");
        return;
    }

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    // IP Header 정보 출력
    printf("IP Header: Src IP: %s, Dst IP: %s\n", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst));

    // TCP 패킷인지 확인
    if (ip_header->ip_p != IPPROTO_TCP) {
        printf("Not a TCP packet.\n");
        return;
    }

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

    // TCP Header 정보 출력
    printf("TCP Header: Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport));

    // 페이로드 (메시지) 출력
    const u_char *payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
    int payload_size = ntohs(ip_header->ip_len) - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);
    
    printf("Payload (%d bytes): ", payload_size);
    for (int i = 0; i < payload_size && i < 16; i++) { // 처음 16바이트만 출력
        printf("%02x ", payload[i]);
    }
    printf("\n\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 네트워크 장치 찾기
    char dev[] = "wlp3s0";  // 또는 "enp2s0"

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 2;
    }

    printf("Using device: %s\n", dev);

    // 패킷 캡처 (TCP 패킷만 필터링)
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        return 2;
    }

    printf("Capturing TCP packets...\n");
    pcap_loop(handle, 10, packet_handler, NULL);

    // 캡처 종료
    pcap_close(handle);
    return 0;
}
