//
// Created by 정유진 on 2018. 9. 28..
//

#include "Bucket.hpp"
#include <netinet/in.h>
#include <string.h>


socket_bucket::socket_bucket() {
    //index = 0;
}

void socket_bucket::is_duplicate(bool dup, struct sockaddr *s_addr) {
    if (files_.checkDuplicate(s_addr)) {
        dup = true;
    } else {
        dup = false;
    }
}

int socket_bucket::bind_socket_by_fd(int s_fd, struct sockaddr *s_addr_ptr, socklen_t socket_len) {
    bool dup = files_.checkDuplicate(s_addr_ptr);
    if (!dup) {
        return files_.bindSocketWithFd(s_fd, s_addr_ptr, socket_len);
        // if error on s_fd, function will return -1.
    } else {
        return -1;
    }
}

void socket_bucket::put_socket(int s_fd, struct socket s) {
    file file_new;

    file_new.fd = s_fd;
    file_new.socket = s;

    files_.pushBack(file_new);
}
void socket_bucket:: print_bucket(){
    files_.print();
}

int socket_bucket::delete_socket(int s_fd) {
    return files_.deleteWithFd(s_fd);
}

void socket_bucket::get_socket_by_fd(int s_fd, struct socket *socket_ptr) {
    file file = files_.getFileWithFd(s_fd);
    struct socket * ret_socket_ptr = (struct socket *)&(file.socket);
    memcpy(socket_ptr, ret_socket_ptr, sizeof(struct socket));
}

file socket_bucket::get_file_by_fd(int s_fd) {
    file file_return = files_.getFileWithFd(s_fd);
    return file_return;
}

file socket_bucket::get_file_by_port(unsigned short port_num, int *error_detection){
    int* no_such_file = (int*)malloc(sizeof(int));
    file file_return = files_.getFileWithPort(port_num, no_such_file);
    file file_trash;
    if ( *(no_such_file) ) /* No Such File */{
        *(error_detection) = 1;
        free(no_such_file);
        return file_trash;
    }
    free(no_such_file);
    return file_return;
//	struct socket file_socket = (struct socket)file.socket;
//	*(socket_ptr_ptr) = &file_socket;
//	printf("=== get socket by port:: port number: %d === \n",
//			((sockaddr_in*) (file_socket.addr_ptr)) -> sin_port );
//	printf("=== get socket by port:: SEQ num: %d === \n",
//			file_socket.SEQ_num );
//	printf("=== get socket by port:: state_machine_ptr: %p === \n",
//				file_socket.state_machine_ptr );
//	printf("=== 2. get socket by port:: port number: %d === \n",
//			((sockaddr_in*) (*socket_ptr_ptr))-> sin_port );
//
//	return file.fd;
}
