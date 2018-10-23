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

    void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *sockaddr_ptr,
                                     socklen_t sock_len) {
        struct sockaddr sockaddr_imsi = *sockaddr_ptr;

        int ret = socket_b.bind_socket_by_fd(fd, &sockaddr_imsi, sock_len);

        returnSystemCall(syscallUUID, ret);
    }

    void TCPAssignment:: syscall_connect(UUID syscallUUID, int pid, int client_fd,
                                         struct sockaddr* server_addr, socklen_t server_addr_length){
        /* Set client addr and port number(= implicit bound),
         * if addr and port have not been set before.
         */
        struct socket client_socket;
        socket_b.get_socket_by_fd(client_fd, &client_socket);

        if (client_socket.addr_ptr == NULL) { // Client socket addr is not set.
            uint8_t* ip_addr_dest;
            uint8_t* ip_addr_src;
            ip_addr_dest = (uint8_t *) malloc( 4 * sizeof(uint8_t) );
            ip_addr_src = (uint8_t *) malloc( 4 * sizeof(uint8_t) );
            *(ip_addr_dest) = (struct sockaddr_in*) server_addr->sin_addr;

            int interface_index;
            interface_index = getHost()->getRoutingTable(ip_addr);
            getHost()->getIPAddr(ip_addr_src, interface_index);

            /* Set addr_ptr of the client socket */
            (struct sockaddr_in *)(client_socket.addr_ptr)->sin_family = AF_INET;
            (struct sockaddr_in *)(client_socket.addr_ptr)->sin_port = (uint16_t) 3000;
            (struct sockaddr_in *)(client_socket.addr_ptr)->sin_addr = (struct in_addr)(*(ip_addr_src));
        }

        /* Send SYN bit to the server.
         */
        Packet* packet_start;
        packet_start = this->allocatePacket(54);

        uint8_t src_ip[4] = (struct sockaddr_in *)(client_socket.addr_ptr)->sin_addr;
        uint8_t dest_ip[4] = ((struct sockaddr_in *)server_addr)->sin_addr;
        uint8_t scr_port[2] = (struct sockaddr_in *)(client_socket.addr_ptr)->sin_port;
        uint8_t dest_port[2] = ((struct sockaddr_in *)server_addr)->sin_port;;

        uint8_t SEQ_num_send[4];
        (* SEQ_num_send) = client_socket.SEQ_num;
        uint8_t ACK_num_send[4];
        (* ACK_num_send) = (uint32_t) 0;

        uint8_t all_flags_send[1];
        all_flags_send[1] = 0x02;

        createPacketHeader(packet_start, src_ip, dest_ip, src_port, dest_port, SEQ_num_send
                , ACK_num_send, all_flags_send);
        this->sendPacket("IPv4", packet_start);

        /* TODO : How to call packetArrived */
        packetArrived

        this->freePacket(packet_start);
    }

    void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int server_fd, int max_backlog){
        /* TODO: Error Detection
         * Is this socket bound before?
         */

        /* TODO
         * Set server_fd to 'listen' the connection request.
         */

        /* TODO
         * Set the max_backlog of the server_fd
         */
    }

    int TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int listen_fd,
                                      struct sockaddr* client_addr, socklen_t* client_addr_len){

        /* TODO: Error detection
         * Is this server socket bound before?
         * Is this server socket set as listen?
         */

        /* TODO
         * while accept any connection request (: queue length of listen_fd == 0 )
         * packetArrived
         */

        /* TODO
         * For the connection request, save them in a not_accepted_file_descriptor
         * After 3-way handshake, move the client fd to accepted_file_descriptor
         */

        /* TODO
         * If there's a connection call, make a new fd and create a socket.
         * Hold the client addr and client addr len.
         */

        /* TODO
         * Return final connection file descriptor
         */
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
                this->syscall_connect(syscallUUID, pid, param.param1_int,
                                      static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
                break;
            case LISTEN:
                this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
                break;
            case ACCEPT:
                this->syscall_accept(syscallUUID, pid, param.param1_int,
                                     static_cast<struct sockaddr*>(param.param2_ptr),
                                     static_cast<socklen_t*>(param.param3_ptr));
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
        /* Extract the IP address and port number of source and destination from the recv pkt */
        uint8_t src_ip[4];
        uint8_t dest_ip[4];
        uint8_t scr_port[2];
        uint8_t dest_port[2];

        packet->readData(14+12, src_ip, 4);
        packet->readData(14+16, dest_ip, 4);
        packet->readData(14+20+0, src_port, 2);
        packet->readData(14+20+2, dest_port, 2);

        /* Read ACK and SYN bit from pkt
         * 1) all_flags_recv, all_flags_send: all 6 bit flag in the packet.
         * 2) ACK_send_bit, SYN_send_bit: bit version of ACK_send and SYN_send */
        uint8_t all_flags_recv[1];
        uint8_t all_flags_send[1];
        uint8_t ACK_send_bit, SYN_send_bit;
        int ACK_recv, SEQ_recv;
        int ACK_send, SEQ_send;

        packet->readData(14+20+13, all_flags_recv, 1);
        all_flags_send[0] = all_flags_recv; /* copy recv packet flags */

        ACK_recv = ( all_flags_recv[0] & 0x10 == 0 )? 0:1;
        SYN_recv = ( all_flags_recv[0] & 0x02 == 0 )? 0:1;

        /* Read ACK num and SEQ num from pkt. */
        uint8_t ACK_num_recv[4];
        uint8_t SEQ_num_recv[4];
        uint8_t ACK_num_send[4];
        uint8_t SEQ_num_send[4];

        packet->readData(14+20+4, SEQ_num_recv, 4);
        packet->readData(14+20+8, ACK_num_recv, 4);


        /* TODO
         * 1. Communicate with dest_port with SYN or ACK bit. (state machine communication)
         * 2. Recv ACK, SYN, ACKnum and SEQnum from state machine. */

        /* Create packet */
        Packet *packet_send;
        packet_send = this->allocatePacket( packet->getSize() );
        packet_send = this->clonePacket(packet);

        /* Set Packet */
        /* ACK bit and SYN bit */
        all_flags_send[1] = all_flags_send[1] & 0xED; /* reset ACK bit and SYN bit */
        SYN_send_bit = (SYN_send) ? 0x02 : 0x00; /* Decide whether SYN bit is on */
        ACK_send_bit = (ACK_send) ? 0x10 : 0x00; /* Decide whether ACK bit is on */
        all_flags_send[1] = ( all_flags_send[1] | SYN_send_bit ) | ACK_send_bit;

        createPacketHeader(packet_send, dest_ip, src_ip, dest_port, src_port,
                           SEQ_num_send, ACK_num_send, all_flags_send);

        /* Sending packet */
        /* TODO:
         *  1) copy the packet
         *  2) If the packet does not arrived properly, re-send the packet
         */
        this->sendPacket("IPv4", packet_send);

        this->freePacket(packet);
    }

    void TCPAssignment::createPacketHeader(Packet* packet_send, uint8_t src_ip[4], uint8_t dest_ip[4],
                                           uint8_t* src_port, uint8_t* dest_port, uint8_t SEQ_num, uint8_t ACK_num, uint8_t* all_flags){
        /* Set Packet */
        /* Src/Dest Ip addr and port number */
        uint16_t checksum;
        packet_send->writeData(14+12, src_ip, 4);
        packet_send->writeData(14+16, dest_ip, 4);
        packet_send->writeData(14+20+0, src_port, 2);
        pakcet_send->writeData(14+20+2, dest_port, 2);

        /* ACK num and SEQ num */
        packet_send->writeData(14+20+4, SEQ_num_send, 4);
        pakcet_send->writeData(14+20+8, ACK_num_send, 4);

        packet_send->writeData(14+20+13, all_flags_send, 1);
        packet_send->writeData(14+20+16, (uint16_t) 0);

        /* Calculating Checksum */
        checksum = checksum((unsigned short*) packet_send, 54);
        packet_send->writeData(14+20+16, checksum);
    }

    void TCPAssignment::timerCallback(void *payload) {

    }


}
/* The reference for the checksum:  http://locklessinc.com/articles/tcp_checksum/
 * @ Name: checksum
 * @ Function: Allow us to calculate TCP checksum */
unsigned short checksum(unsigned short* ptr_packet, int size_packet)
{
    register long c_sum;
    unsigned short oddbyte;
    register short c_sum_final;

    c_sum = 0;

    /* In calculating checksum, we should deal with the odd number byte.
     * While loop calculate the pre-checksum w.o. considering odd number byte.*/
    while( size_packet > 1) {
        c_sum += *ptr_packet ++;
        size_packet -= 2;
    }

    /* Following if statement allows to cope with the 'odd case'.  */
    if( size_packet == 1 ) {
        oddbyte = 0;
        *((u_char*) &oddbyte) = *(u_char*)ptr_packet ;
        c_sum += oddbyte;
    }

    c_sum = (c_sum >> 16) + (c_sum & 0xffff);
    c_sum = c_sum + ( c_sum >> 16 );
    c_sum_final = (short) ~c_sum;

    return (c_sum_final);
}

