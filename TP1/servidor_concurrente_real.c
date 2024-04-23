#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>

// adaptado para funcionamiento con mac, no estoy seguro si corre igual en Linux/Windows!

#define MYPORT 53490
#define BACKLOG 10

int main()
{
    int sockfd, new_fd;
    struct sockaddr_in my_addr;
    struct sockaddr_in their_addr;
    socklen_t sin_size;
    printf("Esta en el socket: %d\n", socket(AF_INET, SOCK_STREAM, 0));

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 1)
    {
        perror("socket");
        exit(1);
    }

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(MYPORT);
    my_addr.sin_addr.s_addr = INADDR_ANY;
    bzero(&(my_addr.sin_zero), 8);

    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1)
    {
        perror("bind");
        exit(1);
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        perror("listen");
        exit(1);
    }

    while (1)
    {
        sin_size = sizeof(struct sockaddr_in);
        if ((new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size)) == -1)
        {
            perror("accept");
            continue;
        }

        printf("server: got connection from %s\n", inet_ntoa(their_addr.sin_addr));

        if (!fork())
        { // proceso hijo
            if (send(new_fd, "Hello, Soap!\n", 14, 0) == -1)
                perror("send");
            close(new_fd);
            exit(0);
        }

        close(new_fd); // proceso padre

        while (waitpid(-1, NULL, WNOHANG) > 0)
            ;
    }

    return 0;
}