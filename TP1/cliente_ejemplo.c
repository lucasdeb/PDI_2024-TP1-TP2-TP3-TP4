#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVERPORT 53490

int main()
{
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    int bytesRead;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        perror("Failed to create socket");
        exit(1);
    }

    // Set up server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVERPORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // localhost

    // Connect to server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1)
    {
        perror("Failed to connect to server");
        exit(1);
    }

    // Receive data from server
    bytesRead = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytesRead == -1)
    {
        perror("Failed to receive data from server");
        exit(1);
    }

    buffer[bytesRead] = '\0'; // Null-terminate the received data
    printf("Received from server: %s\n", buffer);

    // Close socket
    close(sockfd);

    return 0;
}