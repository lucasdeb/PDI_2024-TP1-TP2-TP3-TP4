#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
#include <netinet/ip.h>

#define BUFFER_SIZE 65536

void procesar_paquete(unsigned char *buffer, int size);

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

struct ethhdr
{
    unsigned char h_dest[6];   // Destination MAC address
    unsigned char h_source[6]; // Source MAC address
    uint16_t h_proto;          // Protocol
};

void procesar_paquete(unsigned char *buffer, int size)
{
    struct ethhdr *encabezado_eth = (struct ethhdr *)buffer;

    printf("Paquete recibido - Tamaño: %d bytes\n", size);

    if (size >= sizeof(struct ethhdr) + sizeof(struct iphdr))
    {
        // Packet is Ethernet and has an IP header
        struct iphdr *encabezado_ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        unsigned short longitud_encabezado_ip = encabezado_ip->ihl * 4;
        printf("Paquete IP - Longitud: %d bytes\n", size);
        struct in_addr ip_origen, ip_destino;
        ip_origen.s_addr = encabezado_ip->saddr;
        ip_destino.s_addr = encabezado_ip->daddr;
        printf(" Dirección IP de origen: %s\n", inet_ntoa(ip_origen));
        printf(" Dirección IP de destino: %s\n", inet_ntoa(ip_destino));
        printf(" Dirección MAC de origen: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", encabezado_eth->h_source[0], encabezado_eth->h_source[1], encabezado_eth->h_source[2], encabezado_eth->h_source[3], encabezado_eth->h_source[4], encabezado_eth->h_source[5]);
        printf(" Dirección MAC de destino: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n", encabezado_eth->h_dest[0], encabezado_eth->h_dest[1], encabezado_eth->h_dest[2], encabezado_eth->h_dest[3], encabezado_eth->h_dest[4], encabezado_eth->h_dest[5]);

        if (encabezado_ip->protocol == IPPROTO_TCP)
        {
            struct tcphdr *encabezado_tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + longitud_encabezado_ip);
            printf(" Protocolo: TCP\n");
            printf(" Puerto de origen: %u\n", ntohs(encabezado_tcp->th_sport));
            printf(" Puerto de destino: %u\n", ntohs(encabezado_tcp->th_dport));
        }
        else if (encabezado_ip->protocol == IPPROTO_UDP)
        {
            struct udphdr *encabezado_udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + longitud_encabezado_ip);
            printf(" Protocolo: UDP\n");
            printf(" Puerto de origen: %u\n", ntohs(encabezado_udp->uh_sport));
            printf(" Puerto de destino: %u\n", ntohs(encabezado_udp->uh_dport));
        }
        else if (encabezado_ip->protocol == IPPROTO_ICMP)
        {
            printf(" Protocolo: ICMP\n");
        }
        else
        {
            printf(" Protocolo desconocido\n");
        }
    }
    else
    {
        printf("Paquete no Ethernet\n");
    }
}

int main()
{
    int sockfd;
    unsigned char buffer[BUFFER_SIZE];

    printf("Iniciando sniffer...\n");

    // Crear socket con IPPROTO_IP para capturar todos los paquetes IP entrantes
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_IP)) < 0)
    {
        perror("Error al crear el socket");
        exit(EXIT_FAILURE);
    }

    // Configurar el socket para incluir cabeceras IP
    int one = 1;
    const int *val = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        perror("Error al configurar IP_HDRINCL");
        exit(EXIT_FAILURE);
    }

    // Recibir paquetes indefinidamente
    while (1)
    {
        printf("Esperando paquete...\n");
        int bytes_recibidos = recv(sockfd, buffer, BUFFER_SIZE, 0);
        if (bytes_recibidos < 0)
        {
            perror("recv");
            continue;
        }
        procesar_paquete(buffer, bytes_recibidos);
    }

    close(sockfd);
    return 0;
}