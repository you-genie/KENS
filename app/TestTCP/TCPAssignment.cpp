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
    BlockValue *block_value = new BlockValue;

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
        std::vector<Socket *> new_cli_sockets = std::vector<Socket *>();
        new_sockets.reserve(1024);
        socket_bucket.sockets = new_sockets;
        cli_bucket.sockets = new_cli_sockets;
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
        socket_ptr->pid = pid;
        socket_ptr->is_bind = 0;
        socket_ptr->is_timewait =0 ;

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

    int RemoveConnectionWithPort(uint16_t port, ConnectionBucket *connection_bucket_ptr) {
        for (int i = 0; i < connection_bucket_ptr->connections.size(); i++) {
            Connection *connection_ptr = connection_bucket_ptr->connections[i];
            if (((sockaddr_in *)connection_ptr->cli_addr_ptr)->sin_port == port) {
                connection_bucket_ptr->connections.erase(connection_bucket_ptr->connections.begin() + i);

                return 1;
            }
        }
        return -1;
    }

    int FindParentFdWithPort(uint16_t port, int *fd_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];
            if (((sockaddr_in *)socket_ptr->addr_ptr)->sin_port == port
            && socket_ptr->socket_type != MachineType::SERVER_CLIENT) {
                *fd_ret = socket_ptr->fd;
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

    int FindConnectionWithPort(
            uint16_t port, Connection *connection_ptr_ret, ConnectionBucket *connection_bucket_ptr) {
        for (int i = 0; i < connection_bucket_ptr->connections.size(); i++) {
            Connection *connection_ptr = connection_bucket_ptr->connections[i];
            if (((sockaddr_in *)connection_ptr->cli_addr_ptr)->sin_port == port) {
                memcpy(connection_ptr_ret, connection_ptr, sizeof(Connection));

                return 1;
            }
        }
        //        printf("== Bind Return Point 2 ==\n");
        return -1;
    }

    int FindParentSocketWithPort(uint16_t port, Socket *socket_ptr_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];

            if (((sockaddr_in *)socket_ptr->addr_ptr)->sin_port == port) {

                if (socket_ptr->socket_type != MachineType::SERVER_CLIENT) {
                    memcpy(socket_ptr_ret, socket_ptr, sizeof(Socket));

                    return 1;
                }
            }
        }
        //        printf("== Bind Return Point 2 ==\n");
        return -1;
    }

    int FindChildSocketWithPorts(
            uint16_t my_port, uint32_t peer_ip, Socket *socket_ptr_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];
            if (((sockaddr_in *)socket_ptr->addr_ptr)->sin_port == my_port
            && socket_ptr->socket_type == MachineType::SERVER_CLIENT) {
                if (socket_ptr->peer_values->peer_addr_ptr->sin_addr.s_addr == peer_ip) {
                    memcpy(socket_ptr_ret, socket_ptr, sizeof(Socket));
                    return 1;
                }
            }
        }
        //        printf("== Bind Return Point 2 ==\n");
        return -1;
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
        printf("==== Close call ====\n");
        Socket *socket_temp = new Socket;

        if (FindSocketWithFd(fd, socket_temp, socket_bucket) == -1) {
            // Socket not found.
            returnSystemCall(syscallUUID, -1);
        }

        TCPHeader *packet_header = new TCPHeader;
        packet_header->src_port = ((sockaddr_in *)socket_temp->addr_ptr)->sin_port;

        // Erase this code if later logic is ready
        RemoveSocketWithFd(fd, &socket_bucket);
        removeFileDescriptor(pid, fd);

        delete socket_temp;
        return;
        /* TODO Get peer address */
        // if it's server socket
        if (socket_temp->socket_type == MachineType::SERVER) {
            // TODO: 자식 소켓에게 전부 클로즈 전송한다.
            RemoveSocketWithFd(socket_temp->fd, &socket_bucket);
            delete socket_temp;
            return;
        } else {
            // if it's CLI / SERVER_CLI, find peer from peer value & send FIN.
            packet_header->dest_port = socket_temp->peer_values->peer_addr_ptr->sin_port;
            packet_header->offset_res_flags = 0x01;
            packet_header->seq_num = htonl(socket_temp->seq_num);
            packet_header->ack_num = htonl((uint32_t) 0);
            packet_header->checksum = (uint16_t) 0;

            Packet *packet = this->allocatePacket(54);
            uint32_t *src_ip = &(((sockaddr_in *)socket_temp->addr_ptr)->sin_addr.s_addr);
            /* TODO Get peer address */
            uint32_t *dest_ip = &(socket_temp->peer_values->peer_addr_ptr->sin_addr.s_addr);

            /* send packet */
            CreatePacketHeader(packet, packet_header, src_ip, dest_ip, 20);
            this->sendPacket("IPv4", packet);
            socket_temp->seq_num = socket_temp->seq_num + (uint32_t) 1;

            /* change state to next state */
            StateMachine *state_machine = new StateMachine(socket_temp->state_label, socket_temp->socket_type);
            socket_temp->state_label = (Label) state_machine->Transit(Signal::CLOSE);
            socket_temp->syscallUUID = syscallUUID;
            RemoveSocketWithFd(fd, &socket_bucket);
            socket_bucket.sockets.push_back(socket_temp);
            delete packet_header;
        }
    }

    void TCPAssignment::syscall_getsockname(
            UUID syscallUUID,
            int pid,
            int param1,
            struct sockaddr *param2_ptr, socklen_t *param3_ptr) {

        Socket *socket_ret = new Socket;

        if (E::FindSocketWithFd(param1, socket_ret, this->socket_bucket) != 0) {

            struct sockaddr *addr_ptr_ret = new sockaddr;

            memcpy(addr_ptr_ret, socket_ret->addr_ptr, 16);

            *param2_ptr = *addr_ptr_ret;

            *param3_ptr = sizeof(socket_ret->addr_ptr);

            returnSystemCall(syscallUUID, 0);
        } else if (E::FindSocketWithFd(param1, socket_ret, this->cli_bucket) != 0) {
            debug->Log("SHET!2");

            memcpy(param2_ptr, socket_ret->addr_ptr, sizeof(struct sockaddr));
            *param3_ptr = sizeof(socket_ret->addr_ptr);

            returnSystemCall(syscallUUID, 0);
        } else {
            debug->Log("SHET!3");

            returnSystemCall(syscallUUID, -1);
        }

        delete socket_ret;
    }

    bool isDuplicate(sockaddr_in *addr1, sockaddr_in *addr2) {
        unsigned long s_addr_1 = addr1->sin_addr.s_addr;
        unsigned long s_addr_2 = addr2->sin_addr.s_addr;

        unsigned short port_1 = addr1->sin_port;
        unsigned short port_2 = addr2->sin_port;

        if (s_addr_2 == INADDR_ANY || s_addr_1 == INADDR_ANY) {
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
                returnSystemCall(syscallUUID, -1);
            }
        }

        Socket *socket_ptr_ret = new Socket;
        FindSocketWithFd(fd, socket_ptr_ret, socket_bucket);
        if (socket_ptr_ret->is_bind == 1) /* double Bind request error */
            returnSystemCall(syscallUUID, -1);

        memcpy(socket_ptr_ret->addr_ptr, sockaddr_ptr, sizeof(struct sockaddr));
        socket_ptr_ret->sock_len = sock_len;
        socket_ptr_ret->is_bind = 1;

        RemoveSocketWithFd(fd, &socket_bucket);
        socket_bucket.sockets.push_back(socket_ptr_ret);

        returnSystemCall(syscallUUID, 0);
    }

    void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int client_fd,
                                        struct sockaddr *server_addr, socklen_t server_addr_length) {
        /* Set client addr and port number(= implicit bound),
         * if addr and port have not been set before.
         */
        printf("==== connect call ====\n");
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
        packet_header->head_length = 0x50;
        packet_header->offset_res_flags = 0x02; // 0x02: SYN
        packet_header->seq_num = cli_socket->seq_num;
        packet_header->ack_num = cli_socket->ack_num;
        packet_header->ack_num = (uint16_t) 0;
        packet_header->checksum = (uint16_t) 0;
        packet_header->urgent_ptr = (uint16_t) 0;
        packet_header->window = (uint16_t) 0;

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
        cli_socket->seq_num = cli_socket->seq_num + (uint32_t) 1;

        //        debug->LogDivider();
        RemoveSocketWithFd(client_fd, &socket_bucket);
        socket_bucket.sockets.push_back(cli_socket);

        delete packet_header;
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

        returnSystemCall(syscallUUID, 0);
    }

    void TCPAssignment::CreatePacketHeader(
            Packet *packet, E::TCPHeader *packet_header, uint32_t *src_ip, uint32_t *dest_ip, int length_TCPseg) {
        uint16_t* checksum_ = (uint16_t *) malloc(sizeof(uint16_t));
        *checksum_ = (uint16_t) 0;

        packet->writeData(14+12, src_ip, 4);
        packet->writeData(14+16, dest_ip, 4);

        packet->writeData(14+20, packet_header, 20);

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
        uint8_t* total_structure = (uint8_t *) malloc(total_length);
        memcpy( total_structure, pseudoHeader_temp, 12);
        memcpy( total_structure + 12, packet_header, length_TCPseg);

        *checksum_ = checksum((unsigned short*) total_structure, total_length);
        packet->writeData(14+20+16, checksum_, 2);

        printf("== checksum Test2: %d == \n", *checksum_);

        memcpy( total_structure + 12 + 16 , checksum_, 2);
        uint16_t checksum_test = checksum((unsigned short*) total_structure, total_length);
        printf("== checksum Test3: %d == \n", checksum_test);

        free(checksum_);
        free(TCP_segment);
        free(total_structure);
    }


    void TCPAssignment::CreatePacketHeaderWithFlag(
            uint8_t *flags,
            Socket *socket_ptr,
            Packet *packet,
            E::TCPHeader *packet_header,
            uint32_t *src_ip,
            uint32_t *dest_ip,
            int length) {
        TCPHeader *new_header = new TCPHeader;
        /* Setting head len and flags */
        new_header->head_length = packet_header->head_length;
        new_header->offset_res_flags = *flags;

        new_header->dest_port = htons(ntohs(packet_header->src_port));
        new_header->src_port = htons(ntohs(packet_header->dest_port));
        new_header->ack_num = htonl(ntohl(packet_header->seq_num) + (uint32_t) 1);
        new_header->seq_num = htonl(socket_ptr->seq_num);
        new_header->window = packet_header->window;
        new_header->urgent_ptr = (uint16_t) 0;

        CreatePacketHeader(packet, new_header, src_ip, dest_ip, length);
    }
    void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int listen_fd,
                                       struct sockaddr *client_addr, socklen_t *client_addr_len) {
        debug->Log("syscall_accept");
        Socket *server_socket_ptr = new Socket;
        if (FindSocketWithFd(listen_fd, server_socket_ptr, socket_bucket) == -1) {
            debug->Log("No Socket");
            returnSystemCall(syscallUUID, -1);
        }

        // if socket has recent connection -> child
        if (server_socket_ptr->backlog_ready.size() != 0) {
            int fd = server_socket_ptr->backlog_ready[0];
            Socket *server_cli_socket_ptr = new Socket;
            int i = FindSocketWithFd(fd, server_cli_socket_ptr, socket_bucket);

            memcpy(client_addr, (struct sockaddr *)server_cli_socket_ptr->peer_values->peer_addr_ptr,
                    sizeof(server_cli_socket_ptr->peer_values->peer_addr_ptr));
            server_socket_ptr->backlog_ready.erase(server_socket_ptr->backlog_ready.begin());
            RemoveSocketWithFd(listen_fd, &socket_bucket);
            socket_bucket.sockets.push_back(server_socket_ptr);

            returnSystemCall(syscallUUID, fd);
            return;
        }

        debug->Log("Has NO connection");
        server_socket_ptr->syscallUUID = syscallUUID;

        RemoveSocketWithFd(listen_fd, &socket_bucket);
        socket_bucket.sockets.push_back(server_socket_ptr);

        block_value->fd = listen_fd;
        block_value->pid = pid;
        block_value->sockaddr_ptr = client_addr;
        block_value->socklen_ptr = client_addr_len;
    }

    void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int listen_fd,
                                            struct sockaddr* client_addr, socklen_t *client_addr_len) {
        // Give peer's name
        debug->Log("getpeername");

        // find socket
        Socket *cli_socket_ptr = new Socket;
        if (FindSocketWithFd(listen_fd, cli_socket_ptr, socket_bucket) == -1) {
            debug->Log("No socket in getpeername");
            returnSystemCall(syscallUUID, -1);
        }

        // Get value from peer_values
        memcpy(client_addr,
                (sockaddr *)cli_socket_ptr->peer_values->peer_addr_ptr,
                sizeof(cli_socket_ptr->peer_values->peer_addr_ptr));

        returnSystemCall(syscallUUID, 0);

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
                this->syscall_accept(syscallUUID, pid, param.param1_int,
                                     static_cast<struct sockaddr *>(param.param2_ptr),
                                     static_cast<socklen_t *>(param.param3_ptr));
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
        debug->LogDivider();
        debug->Log("Packet arrived");
        uint32_t *src_ip = new uint32_t;
        uint32_t *dest_ip = new uint32_t;

        TCPHeader *packet_header = new TCPHeader;

        // TODO: get packet header, dest_ip, src_ip
        packet->readData(14 + 12, src_ip, 4);
        packet->readData(14 + 16, dest_ip, 4);
        packet->readData(14 + 20, packet_header, 20);
        // TODO: get packet dest port, and find corresponding socket!
        Socket *dest_socket_ptr = new Socket;

        if (FindParentSocketWithPort(packet_header->dest_port, dest_socket_ptr, socket_bucket) == -1) {
            // PASS
            debug->Log("signal syn?", packet_header->offset_res_flags & 0x02);
            //            debug->LogDivider();
            this->freePacket(packet);
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

        debug->Log("received signal");
        debug->Log(recv);

        StateMachine *state_machine = new StateMachine(dest_socket_ptr->state_label, dest_socket_ptr->socket_type);
        debug->Log(dest_socket_ptr->state_label);

        Signal send = state_machine->GetSendSignalAndSetNextNode(recv);
        debug->Log(send);

        /* Packet Creation */
        if (send == Signal::ERR) {
            returnSystemCall(dest_socket_ptr->syscallUUID, -1);
            this->freePacket(packet);
            return;
        }

        Packet *new_packet = this->clonePacket(packet);
        TCPHeader *new_header = new TCPHeader;

        /* Setting head len and flags */
        new_header->head_length = packet_header->head_length;
        new_header->dest_port = htons(ntohs(packet_header->src_port));
        new_header->src_port = htons(ntohs(packet_header->dest_port));
        new_header->ack_num = htonl(ntohl(packet_header->seq_num) + (uint32_t)1);
        new_header->seq_num = htonl(dest_socket_ptr->seq_num);
        new_header->window = packet_header->window;
        new_header->checksum = (uint16_t) 0;
        new_header->urgent_ptr = (uint16_t) 0;

        /* If the socket is in TIME_WAIT, re-send the ACK to server */
        if(dest_socket_ptr->is_timewait== 1 && dest_socket_ptr->state_label==Label::TIME_WAIT ){
            new_header->offset_res_flags = 0x10;
            CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20);
            this->sendPacket("IPv4", new_packet);

            this->freePacket(packet);
            delete packet_header;
            delete new_header;
            return;
        }

        /* Do appropriate action */
        if (dest_socket_ptr->socket_type == MachineType::SERVER) { /* if the machine is server */
            if (dest_socket_ptr->state_label == Label::LISTEN && syn) {
                if (dest_socket_ptr->backlog->not_established < dest_socket_ptr->max_backlog) {
                    debug->Log("not Established", dest_socket_ptr->backlog->not_established);
                    debug->Log("max backlog", dest_socket_ptr->max_backlog);
                    // ignore other arrived packets.
                    Connection *new_connection_ptr = new Connection;

                    // Set new client address pointer;
                    sockaddr_in *new_cli_addr_ptr = new sockaddr_in;
                    new_cli_addr_ptr->sin_addr.s_addr = *src_ip;
                    new_cli_addr_ptr->sin_family = AF_INET;
                    new_cli_addr_ptr->sin_port = packet_header->src_port;

                    // set client address pointer to new connection pointer
                    new_connection_ptr->cli_addr_ptr = new_cli_addr_ptr;
                    printf("%d: %d\n", new_connection_ptr->cli_addr_ptr->sin_addr.s_addr,
                           new_connection_ptr->cli_addr_ptr->sin_port);

                    // set destination socket (a.k.a. server socket) new connection & raise unestablished one.
                    dest_socket_ptr->backlog->connections.push_back(new_connection_ptr);
                    dest_socket_ptr->backlog->not_established = dest_socket_ptr->backlog->not_established + 1;
                }

                new_header->offset_res_flags = 0x12;
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20);
                this->sendPacket("IPv4", new_packet);

                dest_socket_ptr->state_label = Label::SYN_RCVD;
                dest_socket_ptr->seq_num = (dest_socket_ptr->seq_num) + (uint32_t)1;
                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                this->freePacket(packet);
                delete packet_header;
                delete new_header;
                return;
            }
            else if (dest_socket_ptr->state_label == Label::SYN_RCVD && ack){
                int flag = 0;
                Socket *established_socket_ptr = new Socket;

                for (int i = 0; i < dest_socket_ptr->cli_sockets.size(); i++) {
                    int cli_fd = dest_socket_ptr->cli_sockets[i];
                    Socket *cli_socket = new Socket;
                    FindSocketWithFd(cli_fd, cli_socket, socket_bucket);
                    if (((sockaddr_in *)cli_socket->addr_ptr)->sin_port == packet_header->src_port) {
                        flag = 1;
                    }
                }

                if (flag == 0) {
                    // Create new file descriptor.
                    int fd = 0;
                    fd = createFileDescriptor(dest_socket_ptr->pid);
                    debug->Log("fd", fd);

                    // Set socket values in established_socket_ptr
                    established_socket_ptr->fd = fd;
                    established_socket_ptr->addr_ptr = new sockaddr;

                    established_socket_ptr->protocol = dest_socket_ptr->protocol;
                    established_socket_ptr->state_label = Label::ESTABLISHED;
                    established_socket_ptr->domain = dest_socket_ptr->domain;
                    established_socket_ptr->type = dest_socket_ptr->type;
                    established_socket_ptr->socket_type = MachineType::SERVER_CLIENT;
                    established_socket_ptr->sock_len = dest_socket_ptr->sock_len;

                    established_socket_ptr->seq_num = ntohl(packet_header->ack_num);
                    established_socket_ptr->ack_num = ntohl(packet_header->seq_num) + (uint32_t) 1;
                    established_socket_ptr->addr_ptr = new sockaddr;

                    memcpy(established_socket_ptr->addr_ptr, dest_socket_ptr->addr_ptr, 16);

                    // Set peer value
                    Socket *peer_cli_ptr = new Socket;

                    FindParentSocketWithPort(packet_header->src_port, peer_cli_ptr, socket_bucket);
                    established_socket_ptr->peer_values->peer_fd = peer_cli_ptr->fd;
                    established_socket_ptr->peer_values->peer_addr_ptr = new sockaddr_in;
                    established_socket_ptr->peer_values->peer_addr_ptr->sin_addr.s_addr = *src_ip;
                    established_socket_ptr->peer_values->peer_addr_ptr->sin_port = packet_header->src_port;
                    established_socket_ptr->peer_values->peer_addr_ptr->sin_family = AF_INET;

                }


                // Set ready_backlog for further accept.
                RemoveConnectionWithPort(packet_header->src_port, dest_socket_ptr->backlog);
                dest_socket_ptr->backlog_ready.push_back(established_socket_ptr->fd);

                dest_socket_ptr->backlog->not_established = dest_socket_ptr->backlog->not_established - 1;

                dest_socket_ptr->cli_sockets.push_back(established_socket_ptr->fd);
                dest_socket_ptr->state_label = Label::LISTEN;
                dest_socket_ptr->seq_num = dest_socket_ptr->seq_num + (uint32_t) 1;
                this->freePacket(packet);

                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);
                socket_bucket.sockets.push_back(established_socket_ptr);
                delete new_header;
                delete packet_header;

                // 함수를 다시 불러보쟈...
                this->syscall_accept(
                        dest_socket_ptr->syscallUUID,
                        block_value->pid,
                        block_value->fd,
                        block_value->sockaddr_ptr,
                        block_value->socklen_ptr);
//                returnSystemCall(dest_socket_ptr->syscallUUID, established_socket_ptr->fd);
            }
            else if (dest_socket_ptr->state_label == Label::ESTABLISHED && fin){
                new_header->offset_res_flags = 0x10;
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20);
                this->sendPacket("IPv4", new_packet);

                this->freePacket(packet);
                dest_socket_ptr->state_label = (Label) state_machine->Transit(recv);
                dest_socket_ptr->seq_num = (dest_socket_ptr->seq_num) + (uint32_t)1;

                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                delete packet_header;
                delete new_header;
                return;
            }
            else if (dest_socket_ptr->state_label == Label::LAST_ACK && ack){
                dest_socket_ptr->state_label = (Label) state_machine->Transit(recv);

                delete packet_header;
                delete new_header;
                /* TODO delete the corresponding socket */
            }
        }
        else { /* if the machine is Client */
            if (dest_socket_ptr->state_label == Label::SYN_SENT && syn && ack){
                // Final shake of Handshaking
                printf("== SYN SENT sending ACK to server == \n");
                dest_socket_ptr->state_label = Label::ESTABLISHED;

                // Set peer values
                int peer_fd = 0;
                FindParentFdWithPort(packet_header->src_port, &peer_fd, socket_bucket);
                dest_socket_ptr->peer_values->peer_fd = peer_fd;

                sockaddr_in *new_addr_ptr = new sockaddr_in;
                new_addr_ptr->sin_family = AF_INET;
                new_addr_ptr->sin_addr.s_addr = *src_ip;
                new_addr_ptr->sin_port = packet_header->src_port;

                dest_socket_ptr->peer_values->peer_addr_ptr = new_addr_ptr;

                // Set Seq_num
                dest_socket_ptr->seq_num = (dest_socket_ptr->seq_num) + (uint32_t)1;

                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                // Send Packet
                new_header->offset_res_flags = 0x10;
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20);
                this->sendPacket("IPv4", new_packet);

                this->freePacket(packet);
                delete packet_header;
                delete new_header;
                returnSystemCall(dest_socket_ptr->syscallUUID, 0);
            }
            else if (fin) {
                new_header->offset_res_flags = 0x10;
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20);
                this->sendPacket("IPv4", new_packet);

                dest_socket_ptr->state_label = (Label) state_machine->Transit(recv);
                dest_socket_ptr->seq_num = (dest_socket_ptr->seq_num) + (uint32_t)1;
                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                this->freePacket(packet);
                delete packet_header;
                delete new_header;
                return;
            }
            else if ((dest_socket_ptr->state_label == Label::FIN_WAIT_1 &&  ack) ||
                     (dest_socket_ptr->state_label == Label::CLOSING && ack)){
                dest_socket_ptr->state_label = (Label) state_machine->Transit(recv);
                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                this->freePacket(packet);
                delete packet_header;
                delete new_header;
                return;
            }

        }

        if ( dest_socket_ptr->state_label == Label::TIME_WAIT && dest_socket_ptr->is_timewait == 0){
            /* socket is closed */
            removeFileDescriptor(dest_socket_ptr->pid,dest_socket_ptr->fd);
            /* change the socket state: after timer on */
            dest_socket_ptr->is_timewait = 1;
            RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
            socket_bucket.sockets.push_back(dest_socket_ptr);

            /* Start Timer: waiting for 60 seconds */
            addTimer(dest_socket_ptr, 60);
        }
    }

    void TCPAssignment::timerCallback(void *payload) {
        Socket * socket_temp = (Socket*) payload;
        cancelTimer(socket_temp->syscallUUID);
        RemoveSocketWithFd(socket_temp->fd, &socket_bucket);
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
