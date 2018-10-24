//
// Created by 정유진 on 2018. 9. 28..
//

#ifndef KENSV3_DYNAMICARRAY_H
#define KENSV3_DYNAMICARRAY_H

#endif //KENSV3_DYNAMICARRAY_H

#pragma once

#include <stdio.h>
//#include <sys/socket.h>
#include <netinet/in.h>
#include "SocketVar.hpp"

class DynamicArray {
private:
    file *m_array;
    int m_size; // array size
    int m_used; // 현재 사용 중인 마지막 방 인덱스
    int getFileIndexWithFd(int fd);

    int getFdWithPort(unsigned short port); // return -1 if there's no port.

    bool isDuplicateBind(struct sockaddr_in *addr1, struct sockaddr_in *addr2);

public:
    DynamicArray();

    DynamicArray(int size);

    ~DynamicArray();

    int overlapSocket(int fd, unsigned short port);

    int bindSocketWithFd(int fd, struct sockaddr *s_addr, socklen_t sock_len_new);

    file getFileWithPort(unsigned short port, int* no_such_file);

    void popBack();

    void pushBack(file data);

    void print();

    void deleteWithIndex(int index);

    int deleteWithFd(int fd);

    bool checkDuplicate(struct sockaddr *s_addr); // duplicate 이면 dup에 true value 삽입.

    file getFileWithFd(int fd);

    file &operator[](int index);
};
