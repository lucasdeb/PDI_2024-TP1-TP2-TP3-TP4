#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    const u_char *ip_header = packet + sizeof(struct ether_header);
    struct ip *ip = (struct ip *)ip_header;
    int ip_header_length = ip->ip_hl * 4;

    printf("Src IP: %s\n", inet_ntoa(ip->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip->ip_dst));

    if (ip->ip_p == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)(ip_header + ip_header_length);
        printf("TCP Src Port: %d\n", ntohs(tcp->th_sport));
        printf("TCP Dst Port: %d\n", ntohs(tcp->th_dport));
    }
    else if (ip->ip_p == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)(ip_header + ip_header_length);
        printf("UDP Src Port: %d\n", ntohs(udp->uh_sport));
        printf("UDP Dst Port: %d\n", ntohs(udp->uh_dport));
    }

    printf("\n");
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the device for capturing
    handle = pcap_open_live("en0", BUFSIZ, 0, 1000, errbuf); // (network interface, snaplen, promiscuous mode, timeoout_ms, errbuf)
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return 2;
    }

    // Start capturing packets
    pcap_loop(handle, -1, process_packet, NULL);

    pcap_close(handle);
    return 0;
}