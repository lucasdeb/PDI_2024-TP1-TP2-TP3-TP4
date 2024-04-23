#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <NetworkExtension/NEpacket.h>

#define BUFFER_SIZE 65536

#include <stdint.h>

struct ethhdr
{
    unsigned char h_dest[6];   // Destination MAC address
    unsigned char h_source[6]; // Source MAC address
    uint16_t h_proto;          // Protocol
};

struct iphdr
{
    uint8_t ihl : 4, version : 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

void procesar_paquete(unsigned char *buffer, int size)
{
    printf("Paquete recibido - Longitud: %d bytes\n", size);

    // Encabezado Ethernet
    struct ethhdr *encabezado_eth = (struct ethhdr *)buffer;
    printf("Encabezado Ethernet\n");
    printf("  Dirección MAC de origen: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           encabezado_eth->h_source[0], encabezado_eth->h_source[1], encabezado_eth->h_source[2],
           encabezado_eth->h_source[3], encabezado_eth->h_source[4], encabezado_eth->h_source[5]);
    printf("  Dirección MAC de destino: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           encabezado_eth->h_dest[0], encabezado_eth->h_dest[1], encabezado_eth->h_dest[2],
           encabezado_eth->h_dest[3], encabezado_eth->h_dest[4], encabezado_eth->h_dest[5]);
    printf("  Tipo de protocolo: 0x%.4X\n", ntohs(encabezado_eth->h_proto));

    // Encabezado IP
    struct iphdr *encabezado_ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    printf("Encabezado IP\n");
    printf("  Versión IP: %d\n", encabezado_ip->version);
    printf("  Longitud del encabezado IP: %d bytes\n", encabezado_ip->ihl * 4);
    printf("  Tipo de servicio: %d\n", encabezado_ip->tos);
    printf("  Longitud total: %d bytes\n", ntohs(encabezado_ip->tot_len));
    printf("  Identificación: %d\n", ntohs(encabezado_ip->id));
    printf("  Fragmentación: Flags: %d, Offset: %d\n", (encabezado_ip->frag_off & 0x1FFF), (encabezado_ip->frag_off & 0xE000) >> 13);
    printf("  Tiempo de vida: %d\n", encabezado_ip->ttl);
    printf("  Protocolo: %d\n", encabezado_ip->protocol);
    printf("  Suma de control: 0x%.4X\n", ntohs(encabezado_ip->check));
    printf("  Dirección IP de origen: %s\n", inet_ntoa(*(struct in_addr *)&encabezado_ip->saddr));
    printf("  Dirección IP de destino: %s\n", inet_ntoa(*(struct in_addr *)&encabezado_ip->daddr));

    // Encabezado TCP
    if (encabezado_ip->protocol == IPPROTO_TCP)
    {
        struct tcphdr *encabezado_tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + encabezado_ip->ihl * 4);
        printf("Encabezado TCP\n");
        printf("  Puerto de origen: %d\n", ntohs(encabezado_tcp->th_sport));
        printf("  Puerto de destino: %d\n", ntohs(encabezado_tcp->th_dport));
        printf("  Número de secuencia: %u\n", ntohl(encabezado_tcp->th_seq));
        printf("  Número de acuse de recibo: %u\n", ntohl(encabezado_tcp->th_ack));
        printf("  Longitud de encabezado TCP: %d bytes\n", encabezado_tcp->th_off * 4);
        printf("  Flags: ");
        if (encabezado_tcp->syn)
            printf("SYN ");
        if (encabezado_tcp->ack)
            printf("ACK ");
        if (encabezado_tcp->fin)
            printf("FIN ");
        if (encabezado_tcp->rst)
            printf("RST ");
        if (encabezado_tcp->psh)
            printf("PSH ");
        if (encabezado_tcp->urg)
            printf("URG ");
        printf("\n");
        printf("  Tamaño de ventana: %d\n", ntohs(encabezado_tcp->window));
        printf("  Suma de control: 0x%.4X\n", ntohs(encabezado_tcp->check));
        printf("  Puntero de urgencia: %d\n", ntohs(encabezado_tcp->urg_ptr));
    }

    // Encabezado UDP
    if (encabezado_ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *encabezado_udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + encabezado_ip->ihl * 4);
        printf("Encabezado UDP\n");
        printf("  Puerto de origen: %d\n", ntohs(encabezado_udp->source));
        printf("  Puerto de destino: %d\n", ntohs(encabezado_udp->dest));
        printf("  Longitud total: %d bytes\n", ntohs(encabezado_udp->len));
        printf("  Suma de control: 0x%.4X\n", ntohs(encabezado_udp->check));
    }

    printf("Datos:\n");
    int i;
    for (i = sizeof(struct ethhdr) + encabezado_ip->ihl * 4; i < size; ++i)
    {
        printf("%.2X ", buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    printf("\n");
}

int main()
{
    int sockfd;
    unsigned char buffer[BUFFER_SIZE];

    // Crear un socket raw
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Configurar para recibir desde localhost (loopback)
    struct sockaddr_ll addr;           // Corregir aquí
    socklen_t addr_len = sizeof(addr); // Corregir aquí
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = if_nametoindex("lo");

    // Enlazar el socket a la interfaz loopback
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    // Recibir paquetes
    while (1)
    {
        int bytes_recibidos = recv(sockfd, buffer, sizeof(buffer), 0);
        if (bytes_recibidos < 0)
        {
            perror("recv");
            exit(EXIT_FAILURE);
        }

        procesar_paquete(buffer, bytes_recibidos);
    }

    return 0;
}