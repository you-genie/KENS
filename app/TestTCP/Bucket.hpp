//
// Created by 정유진 on 2018. 9. 28..
//

#ifndef KENSV3_BUCKET_H
#define KENSV3_BUCKET_H

#endif //KENSV3_BUCKET_H

#include "DynamicArray.hpp"
//#include <sys/socket.h>

class socket_bucket {
private:
    DynamicArray files_{1024};
    void is_duplicate(bool dup, struct sockaddr *s_addr);
    //file file_array[100];
    //int index;
    // TODO: implement function find_socket_by_fd(fd: int) := socket
public:
    socket_bucket();

    void put_socket(int s_fd, struct socket s);

    int delete_socket(int s_fd);

    void print_bucket();

    void get_socket_by_fd(int s_fd, struct socket *socket_ptr);

    int bind_socket_by_fd(int s_fd, struct sockaddr *s_addr_ptr, socklen_t sock_len);

//    void
};
