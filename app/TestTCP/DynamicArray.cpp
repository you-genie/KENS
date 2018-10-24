//
// Created by 정유진 on 2018. 9. 28..
//

#include "DynamicArray.hpp"
#include <fcntl.h>
#include <string.h>

DynamicArray::DynamicArray() : m_size(1), m_used(0) {
    m_array = new file[m_size];
}

DynamicArray::DynamicArray(int size) : m_size(size), m_used(0) {
    m_array = new file[m_size];
}

DynamicArray::~DynamicArray() {
    delete[] m_array;
}

void DynamicArray::popBack() {
    if (m_used == 0) return;

    m_used--;
    file *temp = new file[m_used];

    for (int i = 0; i < m_used; i++)
        temp[i] = m_array[i];

    delete[] m_array;
    m_array = new file[m_size];

    for (int i = 0; i < m_used; i++)
        temp[i] = m_array[i];

    delete[] temp;
    return;
}

int DynamicArray::getFileIndexWithFd(int fd) {
    for (int i = 0; i < m_used; i++) {
        file tempFile = m_array[i];
        if (fd == tempFile.fd) {
            return i;
        }
    }
    return -1;
}

file DynamicArray::getFileWithFd(int fd) {
    return m_array[getFileIndexWithFd(fd)];
}

int DynamicArray::getFdWithPort(unsigned short port) {
    for (int i = 0; i < m_used; i++) {
        file f = m_array[i];
        sockaddr_in *s_addr_in = (sockaddr_in*)f.socket.addr_ptr;
        unsigned short f_port = s_addr_in->sin_port;
        if (f_port == port) {
            return f.fd;
        }
    }
    printf("ASDFASDFASDf\n");
    return -1; // no socket with that port
}
file DynamicArray::getFileWithPort(unsigned short port, int* no_such_file) {
    for (int i = 0; i < m_used; i++) {
        file f = m_array[i];
        sockaddr_in *s_addr_in = (sockaddr_in*) malloc(sizeof(sockaddr_in));
        s_addr_in = (sockaddr_in*)f.socket.addr_ptr;
        unsigned short f_port = (unsigned short) s_addr_in->sin_port;
        if (f_port == port) {
            *(no_such_file) = 0;
            return f;
        }
        free(s_addr_in);
    }
    *(no_such_file) = 0;
    file file;
    return file;
}
int DynamicArray::overlapSocket(int fd, unsigned short port) {
    file f = getFileWithFd(fd);
    int fd_overlap = getFdWithPort(port);
    if (fd_overlap != -1) {
        file f_overlap = getFileWithFd(fd);
        struct socket s_overlap = f_overlap.socket;
        f.socket = s_overlap;
        return 0; // No error. success on overlap.
    } else {
        //        return -1; // error. No overlap.
        return -1;
    }
}

bool DynamicArray::isDuplicateBind(struct sockaddr_in *addr1, struct sockaddr_in *addr2) {
    // Rule 1: duplicate if same port in same addr
    // Rule 2: duplicate if same port with 0.0.0.0;
    // Rule 3: not duplicate if dff port with 0.0.0.0 & 0.0.0.0;

    // sockaddr 를 sockaddr_in으로 불러와 port와 addr을 바꾼다.
    // 각각의 port와 addr를 비교한다.
    // addr이 같은데 port가 다른 경우, 무조건 false
    // addr이 다른데 0.0.0.0이고, port가 같은 경우 false.

    unsigned long s_addr_1 = addr1->sin_addr.s_addr;
    unsigned long s_addr_2 = addr2->sin_addr.s_addr;

    unsigned short port_1 = addr1->sin_port;
    unsigned short port_2 = addr2->sin_port;

    if (s_addr_1 == htonl(INADDR_ANY)) {
        if (port_1 != htons(0)) {
            return true; // this one ADDR DUPLICATE
        }
    }

    if (s_addr_1 == s_addr_2) {
        if (port_1 == port_2) {
            return true;
        }
    }

    return false;
}

int DynamicArray::bindSocketWithFd(int fd, struct sockaddr *s_addr, socklen_t sock_len_new) {
    for (int i = 0; i < m_used; i++) {
        int fd_match = m_array[i].fd;
        if (fd == fd_match) {
            m_array[i].socket.addr_ptr = (struct sockaddr*) malloc(sizeof(*s_addr));
            memcpy ( m_array[i].socket.addr_ptr, s_addr, sizeof(*s_addr)) ;

            struct sockaddr_in *s_addr_test = (struct sockaddr_in *) m_array[i].socket.addr_ptr; // for memory problem
            unsigned long s_addr_1 = s_addr_test->sin_addr.s_addr;
            unsigned short port_1 = s_addr_test->sin_port;

            m_array[i].socket.sock_len = sock_len_new;
            return 0;
        }
    }

    return -1;
}

bool DynamicArray::checkDuplicate(struct sockaddr *s_addr) {
    // Check every addr in dynamic array.
    for (int i = 0; i < m_used; i++) {
        struct socket s = m_array[i].socket;

        if(s.addr_ptr == NULL){
            return false; // Test1
        }

        struct sockaddr_in *s_in = (sockaddr_in *)s.addr_ptr;

        if (isDuplicateBind((sockaddr_in *)s.addr_ptr, (sockaddr_in *)s_addr)) {
            return true;
        }
    }
    return false;
}

int DynamicArray::deleteWithFd(int fd) {
    int index = getFileIndexWithFd(fd);
    if (index == -1) {
        // if fd is invalid or socket bound with fd is already closed, use this.
        return -1;
    }
    deleteWithIndex(index);
    return 0;
}

void DynamicArray::deleteWithIndex(int deleted_index) {
    if (m_used == 0) return; // 만약에 지금 array에 아무 것도 없는 경우 어차피 못 지우므로 delete

    // ===Delete process===
    file *temp1 = new file[deleted_index];
    file *temp2 = new file[m_used - deleted_index];

    for (int i = 0; i < deleted_index; i++) {
        temp1[i] = m_array[i];
    }


    for (int i = deleted_index + 1; i < m_used; i++) {
        temp2[i - deleted_index - 1] = m_array[i];
    }

    delete[] m_array;

    m_array = new file[m_size];
    m_used--; // 하나 없앨 것이므로

    for (int i = 0; i < deleted_index; i++) {
        m_array[i] = temp1[i];
    }

    delete[] temp1;

    for (int i = deleted_index; i < m_used; i++) {
        m_array[i] = temp2[i - deleted_index];
    }

    delete[] temp2;
    return;
}

void DynamicArray::pushBack(file data) {
    if (m_size > m_used) {
        m_array[m_used] = data;
        m_used++;
        return;
    }

    file *temp = new file[m_size];

    for (int i = 0; i < m_used; i++)
        temp[i] = m_array[i];

    delete[] m_array;

    m_size *= 2;

    m_array = new file[m_size];

    for (int i = 0; i < m_used; i++)
        m_array[i] = temp[i];

    m_array[m_used] = data;
    m_used++;

    delete[] temp;

    return;
}

/**
 * Helper function for printing out file contents.
 */
void DynamicArray::print() {
    printf("\n===START OF BUCKET===\n");
    for (int i = 0; i < this->m_used; i++) {
        printf("fd %d:: ", this->m_array[i].fd);
        struct sockaddr_in *s_addr_in = (struct sockaddr_in *) this->m_array[i].socket.addr_ptr;
        if (s_addr_in != NULL) {
            printf("Socket:: %lu %hu", s_addr_in->sin_addr.s_addr, s_addr_in->sin_port);
        }
    }
    printf("\n===END OF BUCKET===\n");
}

file &DynamicArray::operator[](int index) {
    return this->m_array[index];
}