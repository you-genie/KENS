/*
 * E_TCPAssignment.cpp
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <string.h>

using E::SocketBucket;
using E::Socket;
using E::Label;
using E::MachineType;
using E::Signal;
using E::Debug;

namespace E {

/**
 * STATIC VARIABLES END
 */

    TCPAssignment::TCPAssignment(Host *host) : HostModule("TCP", host),
                                               NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
                                               SystemCallInterface(AF_INET, IPPROTO_TCP, host),
                                               NetworkLog(host->getNetworkSystem()),
                                               TimerModule(host->getSystem()) {

    }

    TCPAssignment::~TCPAssignment() {

    }

/**
 * Util Functions
 */

    void Debug::ToString(Label label, char *ret_string) {
        switch(label) {
            case Label::CLOSED:
                memcpy(ret_string, "Closed", sizeof("Closed"));
                break;
            case Label::ESTABLISHED:
                memcpy(ret_string, "Established", sizeof("Established"));
                break;
            case Label::LISTEN:
                memcpy(ret_string, "Listen", sizeof("Listen"));
                break;
            case Label::LAST_ACK:
                memcpy(ret_string, "Last Ack", sizeof("Last Ack"));
                break;
            case Label::CLOSE_WAIT:
                memcpy(ret_string, "Close Wait", sizeof("Close Wait"));
                break;
            case Label::FIN_WAIT_1:
                memcpy(ret_string, "Fin Wait 1", sizeof("Fin Wait 1"));
                break;
            case Label::FIN_WAIT_2:
                memcpy(ret_string, "Fin Wait 2", sizeof("Fin Wait 2"));
                break;
            case Label::SYN_RCVD:
                memcpy(ret_string, "Syn Received", sizeof("Syn Received"));
                break;
            case Label::SYN_SENT:
                memcpy(ret_string, "Syn Sent", sizeof("Syn Sent"));
                break;
            case Label::TIME_WAIT:
                memcpy(ret_string, "Time Wait", sizeof("Time Wait"));
                break;
            case Label::NONE:
                memcpy(ret_string, "None", sizeof("None"));
                break;
            default:
                memcpy(ret_string, "Error!", sizeof("Error!"));
                break;
        }
    }

    void Debug::ToString(Signal signal, char *ret_string) {
        switch (signal) {
            case Signal::SYN:
                memcpy(ret_string, "SYN", sizeof("SYN"));
                break;
            case Signal::ACK:
                memcpy(ret_string, "ACK", sizeof("ACK"));
                break;
            case Signal::FIN:
                memcpy(ret_string, "FIN", sizeof("FIN"));
                break;
            case Signal::SYN_ACK:
                memcpy(ret_string, "SYN ACK", sizeof("SYN ACK"));
                break;
            case Signal::FIN_ACK:
                memcpy(ret_string, "FIN ACK", sizeof("FIN ACK"));
                break;
            case Signal::OPEN:
                memcpy(ret_string, "OPEN", sizeof("OPEN"));
                break;
            case Signal::CLOSE:
                memcpy(ret_string, "CLOSE", sizeof("CLOSE"));
                break;
            case Signal::DATA:
                memcpy(ret_string, "DATA", sizeof("DATA"));
                break;
            case Signal::ERR:
                memcpy(ret_string, "ERROR", sizeof("ERROR"));
                break;
            case Signal::NONE:
                memcpy(ret_string, "NONE", sizeof("NONE"));
                break;
            default:
                memcpy(ret_string, "ERROR!", sizeof("ERROR!"));
                break;
        }
    }

    void Debug::ToString(Connection connection, char *ret_string) {
        memcpy(ret_string, &((sockaddr_in *)connection.cli_addr_ptr)->sin_addr.s_addr, sizeof(in_addr));
        strcat(ret_string, ": ");
        memcpy(ret_string, &((sockaddr_in *)connection.cli_addr_ptr)->sin_port, sizeof(uint16_t));
    }

    void Debug::ToString(MachineType machineType, char *ret_string) {
        if (machineType == MachineType::CLIENT) {
            memcpy(ret_string, "Client", 10);
        } else {
            memcpy(ret_string, "Server", 10);
        }
    }

    void Print(sockaddr_in *addr_ptr) {
        printf("Address = %lu : %d\n", addr_ptr->sin_addr.s_addr, addr_ptr->sin_port);
    }

    void TCPAssignment::initialize() {
        std::vector<Socket *> new_sockets = std::vector<Socket *>();
        new_sockets.reserve(1024);
        socket_bucket.sockets = new_sockets;
    }

    void TCPAssignment::finalize() {
    }


    void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int) {
        int fd;

        fd = createFileDescriptor(pid);
        Socket *socket_ptr = new Socket;

        // initialize socket
        socket_ptr->addr_ptr = new sockaddr;
        socket_ptr->sock_len = 0;
        socket_ptr->protocol = PF_INET;
        socket_ptr->domain = param1_int;
        socket_ptr->type = param2_int;
        socket_ptr->state_label = Label::CLOSED;
        socket_ptr->fd = fd;

        socket_ptr->max_backlog = 0;
        socket_ptr->socket_type = MachineType::CLIENT;

        this->socket_bucket.sockets.push_back(socket_ptr);
        returnSystemCall(syscallUUID, fd);
    }

    int RemoveSocketWithFd(int fd, SocketBucket *socket_bucket) {
        for (int i = 0; i < socket_bucket->sockets.size(); i++) {
            //            Socket *socket_ptr = socket_bucket.sockets[i];
            if (socket_bucket->sockets[i]->fd == fd) {
                socket_bucket->sockets.erase(socket_bucket->sockets.begin() + i);

                return 1;
            }
        }
        return -1; // error occured
    }

    int FindSocketWithFd(int fd, Socket *socket_ptr_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];
            if (socket_ptr->fd == fd) {
                memcpy(socket_ptr_ret, socket_ptr, sizeof(Socket));
                //                socket_ptr_ret = socket_ptr;
                return 1;
            }
        }
        return -1; // Error occured.
    }

    int FindSocketWithPort(uint16_t port, Socket *socket_ptr_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];
            if (((sockaddr_in *)socket_ptr->addr_ptr)->sin_port == port) {
                memcpy(socket_ptr_ret, socket_ptr, sizeof(Socket));

                return 1;
            }
        }
//        printf("== Bind Return Point 2 ==\n");
        return -1;
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
        removeFileDescriptor(pid, fd);

        int ret = RemoveSocketWithFd(fd, &socket_bucket);
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
            struct sockaddr *param2_ptr, socklen_t *param3_ptr) {

        Socket *socket_ret = new Socket;

        if (E::FindSocketWithFd(param1, socket_ret, this->socket_bucket) != 0) {

            memcpy(param2_ptr, socket_ret->addr_ptr, sizeof(struct sockaddr));
            memcpy(param3_ptr, &(socket_ret->sock_len), sizeof(socklen_t));

            returnSystemCall(syscallUUID, 0);
        } else {
            returnSystemCall(syscallUUID, -1);
        }

        delete socket_ret;
    }

    bool isDuplicate(sockaddr_in *addr1, sockaddr_in *addr2) {

        unsigned long s_addr_1 = addr1->sin_addr.s_addr;
        unsigned long s_addr_2 = addr2->sin_addr.s_addr;

        unsigned short port_1 = addr1->sin_port;
        unsigned short port_2 = addr2->sin_port;

        if (s_addr_1 == htonl(INADDR_ANY)) {
            if (port_1 == port_2) {
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

    void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *sockaddr_ptr,
                                     socklen_t sock_len) {
        struct sockaddr_in *sockaddr_ptr_new = (sockaddr_in *)sockaddr_ptr ;

        int dup = 0;
        // compare inside the bucket.
        for (int i = 0; i < this->socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = this->socket_bucket.sockets[i];

            sockaddr_in *base_addr = (sockaddr_in *) (socket_ptr->addr_ptr);
            if (isDuplicate(base_addr, (sockaddr_in *) sockaddr_ptr)) {
//                printf("== Bind Return Point 10 ==\n");
                returnSystemCall(syscallUUID, -1);
                dup = 1;
            }
        }

        if (dup != 1) {
            Socket *socket_ptr_ret = new Socket;
            FindSocketWithFd(fd, socket_ptr_ret, socket_bucket);

            memcpy(socket_ptr_ret->addr_ptr, sockaddr_ptr, sizeof(struct sockaddr));

            socket_ptr_ret->sock_len = sock_len;

            RemoveSocketWithFd(fd, &socket_bucket);
            socket_bucket.sockets.push_back(socket_ptr_ret);

            returnSystemCall(syscallUUID, 0);
        }
    }

    void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int client_fd,
                                        struct sockaddr *server_addr, socklen_t server_addr_length) {
        /* Set client addr and port number(= implicit bound),
         * if addr and port have not been set before.
         */

        // TODO: Find Socket.
        Socket *cli_socket = new Socket;

        if (FindSocketWithFd(client_fd, cli_socket, socket_bucket) == -1) {
            // Socket not found.
            returnSystemCall(syscallUUID, -1);
        }

        // TODO: set client addr and port number! (dup check also...?)
        int interface_index;

        in_addr_t *ip_addr_dest_ptr = &(((sockaddr_in *)server_addr)->sin_addr.s_addr);
        in_addr_t *ip_addr_src_ptr = new in_addr_t;
        interface_index = getHost()->getRoutingTable((const uint8_t *)ip_addr_dest_ptr);
        getHost()->getIPAddr((uint8_t *)ip_addr_src_ptr, interface_index);

        sockaddr_in *cli_addr_ptr = new sockaddr_in;
        cli_addr_ptr->sin_family = AF_INET;
        cli_addr_ptr->sin_port = htons((uint16_t) 30000);
        cli_addr_ptr->sin_addr.s_addr = (u_long) ip_addr_src_ptr;

        cli_socket->addr_ptr = (struct sockaddr *)cli_addr_ptr;
        cli_socket->sock_len = *(&server_addr_length);
        cli_socket->seq_num = 0;
        cli_socket->ack_num = 0;

        Print((sockaddr_in *)cli_socket->addr_ptr);

        // TODO: set packet header & packet
        TCPHeader *packet_header = new TCPHeader;
        packet_header->src_port = ((sockaddr_in *)cli_socket->addr_ptr)->sin_port;
        packet_header->dest_port = ((sockaddr_in *)server_addr)->sin_port;
        packet_header->offset_res_flags = 0x02; // 0x02: SYN
        packet_header->seq_num = cli_socket->seq_num;
        packet_header->ack_num = cli_socket->ack_num;

        Packet *packet = this->allocatePacket(54);

        uint32_t *src_ip = &(((sockaddr_in *)cli_socket->addr_ptr)->sin_addr.s_addr);
        uint32_t *dest_ip = &(((sockaddr_in *)server_addr)->sin_addr.s_addr);

        // TODO: send packet
        CreatePacketHeader(packet, packet_header, src_ip, dest_ip, 20);
        this->sendPacket("IPv4", packet);

        // TODO: change state to SYN_SENT
        cli_socket->state_label = Label::SYN_SENT;

        // TODO: change each states of socket.
        cli_socket->socket_type = MachineType::CLIENT;
        cli_socket->syscallUUID = syscallUUID;
        RemoveSocketWithFd(client_fd, &socket_bucket);
        socket_bucket.sockets.push_back(cli_socket);
    }

    void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int server_fd, int max_backlog) {
        /* TODO: Error Detection
         * Is this socket bound before?
         */
        Socket *socket_ptr = new Socket;
        if (FindSocketWithFd(server_fd, socket_ptr, socket_bucket) == -1) {
            // Error found on connect.
            returnSystemCall(syscallUUID, -1);
        }

        // TODO: set max_backlog to socket.
        socket_ptr->max_backlog = max_backlog;

        // TODO: set backlog.
        ConnectionBucket *backlog = new ConnectionBucket;
        backlog->connections = std::vector<Connection *>();
        backlog->connections.reserve(max_backlog);
        socket_ptr->backlog = backlog;

        // TODO: set state to LISTEN.
        socket_ptr->state_label = Label::LISTEN;
        socket_ptr->socket_type = MachineType::SERVER;
        socket_ptr->syscallUUID = syscallUUID;
        RemoveSocketWithFd(server_fd, &socket_bucket);
        socket_bucket.sockets.push_back(socket_ptr);

        returnSystemCall(syscallUUID, 1);
    }

    void TCPAssignment::CreatePacketHeader(
            Packet *packet, E::TCPHeader *packet_header, uint32_t *src_ip, uint32_t *dest_ip, int length_TCPseg) {
        uint16_t *checksum_;
        checksum_ = (uint16_t*) malloc(sizeof(uint16_t));
        *checksum_ = (uint16_t) 0;

        packet->writeData(14+12, src_ip, 4);
        packet->writeData(14+16, dest_ip, 4);

        packet->writeData(14+20, packet_header, 20);
        packet->writeData(14+20+16, checksum_, 2);

        /* TODO pseudoheader for checksum calculation */
        /* Calculating Checksum */
        pseudoHeader *pseudoHeader_temp = new pseudoHeader;

        uint8_t* TCP_segment = (uint8_t*) malloc(length_TCPseg);
        memcpy(TCP_segment, packet_header, length_TCPseg);

        pseudoHeader_temp->src_ip = *src_ip;
        pseudoHeader_temp->dest_ip = *dest_ip;
        pseudoHeader_temp->reserved = (uint8_t) 0;
        pseudoHeader_temp->protocol = (uint8_t) 6;
        pseudoHeader_temp->TCP_segment_length = htons((uint16_t)length_TCPseg);

        int total_length = 12 + length_TCPseg;
//        printf("== total Length : %d == \n", total_length);
        uint8_t* total_structure = (uint8_t *) malloc(total_length);
        memcpy( total_structure, pseudoHeader_temp, 12);
        memcpy( total_structure + 12, TCP_segment, length_TCPseg);

        *checksum_ = checksum((unsigned short*) total_structure, total_length);
        packet->writeData(14+20+16, checksum_, 2);
        free(total_structure);
        free(TCP_segment);
    }

    void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int listen_fd,
                                       struct sockaddr *client_addr, socklen_t *client_addr_len) {


    }

    void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int listen_fd,
                                            struct sockaddr* client_addr, socklen_t *client_addr_len) {
        // Give peer's name

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
                                      static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t) param.param3_int);
                break;
            case LISTEN:
                this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
                break;
            case ACCEPT:
                //                this->syscall_accept(syscallUUID, pid, param.param1_int,
                //                                     static_cast<struct sockaddr *>(param.param2_ptr),
                //                                     static_cast<socklen_t *>(param.param3_ptr));
                break;
            case BIND:
                this->syscall_bind(syscallUUID, pid, param.param1_int,
                                   static_cast<struct sockaddr *>(param.param2_ptr),
                                   (socklen_t) param.param3_int);
                break;
            case GETSOCKNAME:
                this->syscall_getsockname(syscallUUID, pid, param.param1_int,
                                          static_cast<struct sockaddr *>(param.param2_ptr),
                                          static_cast<socklen_t *>(param.param3_ptr));
                break;
            case GETPEERNAME:
                this->syscall_getpeername(syscallUUID, pid, param.param1_int,
                                          static_cast<struct sockaddr *>(param.param2_ptr),
                                          static_cast<socklen_t*>(param.param3_ptr));
                break;
            default:
                assert(0);
        }
    }

    void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {
        /* Extract the IP address and port number of source and destination from the recv pkt */
        /* Extract the IP address and port number of source and destination from the recv pkt */
//        printf("===PACKET ARRIVED===\n");

        uint32_t *src_ip = new uint32_t;
        uint32_t *dest_ip = new uint32_t;

        TCPHeader *packet_header = new TCPHeader;

        // TODO: get packet header, dest_ip, src_ip
        packet->readData(14 + 12, src_ip, 4);
        packet->readData(14 + 16, dest_ip, 4);
        packet->readData(14 + 20, packet_header, 20);
        // TODO: get packet dest port, and find corresponding socket!
        Socket *dest_socket_ptr = new Socket;
        if (FindSocketWithPort(packet_header->dest_port, dest_socket_ptr, socket_bucket) == -1) {
            // PASS
            return;
        };

        // TODO: get Signal from packet header
        bool syn = packet_header->offset_res_flags & 0x02;
        bool ack = packet_header->offset_res_flags & 0x10;
        bool fin = packet_header->offset_res_flags & 0x01;
        Signal recv;

        if (syn) {
            if (ack) {
                recv = Signal::SYN_ACK;
            } else {
                recv = Signal::SYN;
            }
        } else if (ack) {
            if (fin) {
                recv = Signal::FIN_ACK;
            } else {
                recv = Signal::ACK; //change
            }
        } else if (fin) {
            recv = Signal::FIN;
        } else {
            recv = Signal::NONE;
        }

        Debug::Log(recv, debug_str);
//        printf("recv: %s\n", debug_str);


//        // TODO: if SYN, check whether it's valid with max.
//
//        // TODO: if SYN, do SYN related action
//        StateMachine *state_machine = new StateMachine(dest_socket_ptr->state_label, dest_socket_ptr->socket_type);
//        ToString(dest_socket_ptr->state_label, debug_str);
////        printf("%s, %d\n", debug_str, dest_socket_ptr->socket_type);
//
//        Signal send = state_machine->GetSendSignalAndSetNextNode(recv);
//        ToString(send, debug_str);
////        printf("action: %s\n", debug_str);
//
//        if (send == Signal::ERR) {
//            return;
//        } else if (send == Signal::SYN_ACK) {
//            Packet *new_packet = this->clonePacket(packet);
//            TCPHeader *new_header = new TCPHeader;
//            /* Setting head len and flags */
//            new_header->head_length = packet_header->head_length;
//            new_header->offset_res_flags = 0x12;
//
//            new_header->dest_port = htons(ntohs(packet_header->src_port));
//            new_header->src_port = htons(ntohs(packet_header->dest_port));
//            new_header->ack_num = htonl(ntohl(packet_header->seq_num) + (uint32_t)1);
//            new_header->seq_num = htonl(dest_socket_ptr->seq_num);
//            new_header->window = packet_header->window;
//            new_header->urgent_ptr = (uint16_t) 0;
//
//            CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20);
//            this->sendPacket("IPv4", new_packet);
////            printf("Sending Signal\n");
//            free(new_header);
//        } else {
//            // TODO: other actions
//        }
//
//        dest_socket_ptr->state_label = (Label) state_machine->Transit(recv);
//        if (dest_socket_ptr->state_label == Label::ESTABLISHED) {
//            returnSystemCall(dest_socket_ptr->syscallUUID, 1);
//        }
//        char* state_str = (char*)malloc(4);
//        ToString(dest_socket_ptr->state_label, state_str);
////        printf("Label: %s\n", state_str);
//        free(state_str);
//
//
//        this->freePacket(packet);
//        free(state_machine);
//        free(dest_ip);
//        free(src_ip);
//        free(packet_header);
        // TODO: if SYN ACK, do SYN ACK related action
    }

    void TCPAssignment::timerCallback(void *payload) {

    }

/* The reference for the checksum:  http://locklessinc.com/articles/tcp_checksum/
 * @ Name: checksum
 * @ Function: Allow us to calculate TCP checksum */
    unsigned short TCPAssignment::checksum(unsigned short* ptr_packet, int size_packet)
    {
        register long c_sum;
        unsigned short oddbyte;
        register short c_sum_final;

        unsigned short* new_packet = ptr_packet;
        //        unsigned short* new_packet_ptr = new_packet;
        //        memcpy(new_packet, ptr_packet, size_packet);
        c_sum = 0;

        /* In calculating checksum, we should deal with the odd number byte.
         * While loop calculate the pre-checksum w.o. considering odd number byte.*/
        while( size_packet > 1) {
            c_sum += *new_packet ++;
            size_packet -= 2;
        }

        /* Following if statement allows to cope with the 'odd case'.  */
        if( size_packet == 1 ) {
            oddbyte = 0;
            *((u_char*) &oddbyte) = *(u_char*)new_packet ;
            c_sum += oddbyte;
        }

        c_sum = (c_sum >> 16) + (c_sum & 0xffff);
        c_sum = c_sum + ( c_sum >> 16 );
        c_sum_final = (short) ~c_sum;

        //        free(new_packet_ptr);
        return (c_sum_final);
    }

    Signal StateMachine::GetSendSignalAndSetNextNode(E::Signal recv) {
        if (machine_type == MachineType::CLIENT) {
            switch (current_node) {
                case Label::CLOSED:
                    if (recv == Signal::OPEN) {
                        next_node = Label::SYN_SENT;
                        return Signal::SYN;
                    } else {
                        return Signal::ERR;
                    }
                case Label::SYN_SENT:
                    if (recv == Signal::CLOSE || recv == Signal::ERR) {
                        next_node = Label::CLOSED;
                        return Signal::NONE;
                    } else if (recv == Signal::SYN_ACK) {
                        next_node = Label::ESTABLISHED;
                        return Signal::ACK;
                    } else {
                        return Signal::ERR;
                    }
                case Label::ESTABLISHED:
                    if (recv == Signal::CLOSE) {
                        next_node = Label::FIN_WAIT_1;
                        return Signal::FIN;
                    } else {
                        return Signal::ERR;
                    }
                case Label::FIN_WAIT_1:
                    if (recv == Signal::ACK) {
                        next_node = Label::FIN_WAIT_2;
                        return Signal::NONE;
                    } else if (recv == Signal::FIN) {
                        next_node = Label::CLOSING;
                        return Signal::ACK;
                    } else if (recv == Signal::FIN_ACK) {
                        next_node = Label::TIME_WAIT;
                        return Signal::ACK;
                    } else {
                        return Signal::ERR;
                    }
                case Label::FIN_WAIT_2:
                    if (recv == Signal::FIN) {
                        next_node = Label::TIME_WAIT;
                        return Signal::ACK;
                    } else {
                        return Signal::ERR;
                    }
                case Label::CLOSING:
                    if (recv == Signal::ACK) {
                        next_node = Label::TIME_WAIT;
                        return Signal::NONE;
                    } else {
                        return Signal::ERR;
                    }
                case Label::TIME_WAIT:
                    if (recv == Signal::ERR) {
                        next_node = Label::CLOSED;
                        return Signal::NONE;
                    } else {
                        return Signal::ERR;
                    }

            }
        } else {
            switch (current_node) {
                case Label::CLOSED:
                    if (recv == Signal::OPEN) {
                        next_node = Label::LISTEN;
                        return Signal::NONE;
                    } else {
                        return Signal::ERR;
                    }
                case Label::LISTEN:
                    if (recv == Signal::SYN) {
                        next_node = Label::SYN_RCVD;
                        return Signal::SYN_ACK;
                    } else {
                        return Signal::ERR;
                    }
                case Label::SYN_RCVD:
                    if (recv == Signal::ERR) {
                        next_node = Label::CLOSED;
                        return Signal::NONE;
                    } else if (recv == Signal::ACK) {
                        next_node = Label::ESTABLISHED;
                        return Signal::NONE;
                    } else {
                        return Signal::ERR;
                    }
                case Label::ESTABLISHED:
                    if (recv == Signal::FIN) {
                        next_node = Label::CLOSE_WAIT;
                        return Signal::ACK;
                    } else {
                        return Signal::ERR;
                    }
                case Label::CLOSE_WAIT:
                    if (recv == Signal::CLOSE) {
                        next_node = Label::LAST_ACK;
                        return Signal::FIN;
                    } else {
                        return Signal::ERR;
                    }
                case Label::LAST_ACK:
                    if (recv == Signal::ACK) {
                        next_node = Label::CLOSED;
                        return Signal::NONE;
                    } else {
                        return Signal::ERR;
                    }
            }

        }
    }

    int StateMachine::Transit(E::Signal recv) {
        Signal signal = GetSendSignalAndSetNextNode(recv);
        if (signal == Signal::ERR) {
            return -1; // Error
        }

        current_node = next_node;
        return (int)current_node;
    }

}