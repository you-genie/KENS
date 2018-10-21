/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include "Bucket.hpp"
#include <string.h>

namespace E {

    TCPAssignment::TCPAssignment(Host *host) : HostModule("TCP", host),
                                               NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
                                               SystemCallInterface(AF_INET, IPPROTO_TCP, host),
                                               NetworkLog(host->getNetworkSystem()),
                                               TimerModule(host->getSystem()) {

    }

    TCPAssignment::~TCPAssignment() {

    }

    void TCPAssignment::initialize() {
        typedef struct socket socket;

    }

    void TCPAssignment::finalize() {

    }

    socket_bucket socket_b;

    void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int) {
        int fd;

        fd = createFileDescriptor(pid);
        struct socket socket_put;
//   socket_ptr = (socket*) malloc(sizeof(socket));

        socket_put.domain = param1_int;
        socket_put.type = param2_int;
        socket_put.protocol = IPPROTO_TCP;
        socket_put.sock_len = 0;

        socket_b.put_socket(fd, socket_put);

        returnSystemCall(syscallUUID, fd);
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
        removeFileDescriptor(pid, fd);
        int ret = socket_b.delete_socket(fd);
        if (ret == -1) {
            returnSystemCall(syscallUUID, ret);
        } else {
            returnSystemCall(syscallUUID, fd);
        }
    }

    void TCPAssignment::syscall_getsockname(
            UUID syscallUUID,
            int pid,
            int param1,
            struct sockaddr *param2_ptr, socklen_t* param3_ptr) {
        struct socket socket_ret;

        socket_b.get_socket_by_fd(param1, &socket_ret);

        /* Copy socket address */
        if (socket_ret.addr_ptr == NULL) {
            // You can't get address value, it's null!
            returnSystemCall(syscallUUID, -1);
        }
        memcpy(param2_ptr, socket_ret.addr_ptr, sizeof(struct sockaddr));

        /* Copy socket address length */
        memcpy(param3_ptr, &socket_ret.sock_len, sizeof(socklen_t));


        returnSystemCall(syscallUUID, 0);
        //need to change this
    }

    void TCPAssignment::syscall_bind(UUID syscallUUId, int pid, int fd, struct sockaddr *sockaddr_ptr,
                                     socklen_t sock_len) {
    	struct sockaddr sockaddr_imsi = *sockaddr_ptr;

        int ret = socket_b.bind_socket_by_fd(fd, &sockaddr_imsi, sock_len);

        returnSystemCall(syscallUUId, ret);
    }

    void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter &param) {
        switch (param.syscallNumber) {
            case SOCKET:
                this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
                break;
            case CLOSE:
                this->syscall_close(syscallUUID, pid, param.param1_int);
                break;
            case READ:
                //this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
                break;
            case WRITE:
                //this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
                break;
            case CONNECT:
                //this->syscall_connect(syscallUUID, pid, param.param1_int,
                //		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
                break;
            case LISTEN:
                //this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
                break;
            case ACCEPT:
                //this->syscall_accept(syscallUUID, pid, param.param1_int,
                //		static_cast<struct sockaddr*>(param.param2_ptr),
                //		static_cast<socklen_t*>(param.param3_ptr));
                break;
            case BIND:
                this->syscall_bind(syscallUUID, pid, param.param1_int,
                		static_cast<struct sockaddr *>(param.param2_ptr),
                		(socklen_t) param.param3_int);
                break;
            case GETSOCKNAME:
                this->syscall_getsockname(syscallUUID, pid, param.param1_int,
                		static_cast<struct sockaddr *>(param.param2_ptr),
                		static_cast<socklen_t*>(param.param3_ptr));
                break;
            case GETPEERNAME:
                //this->syscall_getpeername(syscallUUID, pid, param.param1_int,
                //		static_cast<struct sockaddr *>(param.param2_ptr),
                //		static_cast<socklen_t*>(param.param3_ptr));
                break;
            default:
                assert(0);
        }
    }

    void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {

    }

    void TCPAssignment::timerCallback(void *payload) {

    }


}
