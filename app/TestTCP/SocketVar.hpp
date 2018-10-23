//
// Created by 정유진 on 2018. 9. 28..
//

#ifndef KENSV3_SOCKET_H
#define KENSV3_SOCKET_H

#endif //KENSV3_SOCKET_H

#include <stdlib.h>

//#include <sys/socket.h>
//
//struct sockaddr {
//    unsigned short sa_family;
//    char sa_data[14];
//};

struct socket {
    void *state_machine; // later be defined in TCPassignment
    int domain;
    int type;
    int protocol;
    struct sockaddr* addr_ptr = NULL; // NULL
    socklen_t sock_len;
    uint32_t SEQ_num;
    int max_backlog;
    int clientaddr_defined = 0;
};

struct file {
    int fd;
    struct socket socket;

};
