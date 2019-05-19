#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<sys/un.h>

#define CMD_MAX_LEN 50

char* sock_path = "/data/local/tmp/EvMonitor_agent/sock";

int main() {
    struct sockaddr_un listen_addr, client_addr;
    int listen_fd, connect_fd;
    socklen_t client_addr_len;
    char buff[CMD_MAX_LEN + 1];
    char input_buff[50];

    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sun_family = AF_UNIX;
    strcpy(listen_addr.sun_path, sock_path);
    unlink(sock_path);
    if (bind(listen_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind error");
        exit(1);
    }

    if (listen(listen_fd, 20) < 0) {
        perror("listen error");
        exit(1);
    }
    printf("waiting for client\n");
    while(1) {
        connect_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (connect_fd < 0) {
            perror("accept error");
            break;
        } 

        if (connect_fd == 0) {
            printf("read EOF\n");
            continue;
        }
        printf("client connected, addr[%s]\n", client_addr.sun_path);
        while(1) {
            scanf("%s", input_buff);
            if (input_buff[0] == 'q') {
                exit(0);
            }
            if (write(connect_fd, input_buff, strlen(input_buff) + 1) < 0) {
                perror("write error");
            }
        }
        

    }
    close(listen_fd);
}