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
//    BlockValue *block_value = new BlockValue;
//    BlockValue *listen_value = new BlockValue;

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
        switch (label) {
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
        memcpy(ret_string, &((sockaddr_in *) connection.cli_addr_ptr)->sin_addr.s_addr, sizeof(in_addr));
        strcat(ret_string, ": ");
        memcpy(ret_string, &((sockaddr_in *) connection.cli_addr_ptr)->sin_port, sizeof(uint16_t));
    }

    void Debug::ToString(MachineType machineType, char *ret_string) {
        if (machineType == MachineType::CLIENT) {
            memcpy(ret_string, "Client", 10);
        } else if (machineType == MachineType::SERVER) {
            memcpy(ret_string, "Server", 10);
        } else
            memcpy(ret_string, "ServerC", 10);
    }

    void Print(sockaddr_in *addr_ptr) {
        printf("Address = %lu : %d\n", addr_ptr->sin_addr.s_addr, addr_ptr->sin_port);
    }

    void TCPAssignment::initialize() {
        std::vector < Socket * > new_sockets = std::vector<Socket *>();
        std::vector < Socket * > new_cli_sockets = std::vector<Socket *>();
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
        socket_ptr->is_timewait = 0;

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

    int RemoveConnectionWithIp(uint32_t ip, ConnectionBucket *connection_bucket_ptr) {
        for (int i = 0; i < connection_bucket_ptr->connections.size(); i++) {
            Connection *connection_ptr = connection_bucket_ptr->connections[i];
            if (((sockaddr_in *) connection_ptr->cli_addr_ptr)->sin_addr.s_addr == ip) {
                connection_bucket_ptr->connections.erase(connection_bucket_ptr->connections.begin() + i);

                return 1;
            }
        }
        return -1;
    }

    int FindParentFdWithPort(uint16_t port, int *fd_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];
            if (((sockaddr_in *) socket_ptr->addr_ptr)->sin_port == port
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
                return 1;
            }
        }
        return -1; // Error occured.
    }

    int FindConnectionWithPort(
            uint16_t port, Connection *connection_ptr_ret, ConnectionBucket *connection_bucket_ptr) {
        for (int i = 0; i < connection_bucket_ptr->connections.size(); i++) {
            Connection *connection_ptr = connection_bucket_ptr->connections[i];
            if (((sockaddr_in *) connection_ptr->cli_addr_ptr)->sin_port == port) {
                memcpy(connection_ptr_ret, connection_ptr, sizeof(Connection));

                return 1;
            }
        }
        return -1;
    }

    int FindParentSocketWithPort(uint16_t port, Socket *socket_ptr_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];
            if (((sockaddr_in *) socket_ptr->addr_ptr)->sin_port == port) {

                if (socket_ptr->socket_type != MachineType::SERVER_CLIENT) {
                    memcpy(socket_ptr_ret, socket_ptr, sizeof(Socket));

                    return 1;
                }
            }
        }
        return -1;
    }

    int FindChildSocketWithPorts(
            uint16_t my_port, uint32_t peer_ip, Socket *socket_ptr_ret, SocketBucket socket_bucket) {
        for (int i = 0; i < socket_bucket.sockets.size(); i++) {
            Socket *socket_ptr = socket_bucket.sockets[i];
            if (((sockaddr_in *) socket_ptr->addr_ptr)->sin_port == my_port
                && socket_ptr->socket_type == MachineType::SERVER_CLIENT) {
                if (socket_ptr->peer_values->peer_addr_ptr->sin_addr.s_addr == peer_ip) {
                    memcpy(socket_ptr_ret, socket_ptr, sizeof(Socket));
                    return 1;
                }
            }
        }
        return -1;
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
        //	debug->BigLog("syscall_close");
        Socket *socket_temp = new Socket;

        if (FindSocketWithFd(fd, socket_temp, socket_bucket) == -1) {
            /* ERROR: Socket not found. */
            returnSystemCall(syscallUUID, -1);
        }

        if (socket_temp->state_label == Label::CLOSED) {
            int ret = RemoveSocketWithFd(fd, &socket_bucket);
            if (ret == -1) {
                returnSystemCall(syscallUUID, -1);
            } else {
                removeFileDescriptor(pid, fd);
                returnSystemCall(syscallUUID, fd);
            }
        } else {
            debug->Log(socket_temp->state_label);
            TCPHeader *packet_header = new TCPHeader;
            packet_header->src_port = ((sockaddr_in *) socket_temp->addr_ptr)->sin_port;
            packet_header->dest_port = socket_temp->peer_values->peer_addr_ptr->sin_port;
            packet_header->offset_res_flags = 0x01;
            packet_header->head_length = 0x50;
            packet_header->seq_num = htonl(socket_temp->seq_num);
            packet_header->ack_num = htonl((uint32_t) 0);
            packet_header->checksum = (uint16_t) 0;

            Packet *packet = this->allocatePacket(54);
            uint32_t *src_ip = &(((sockaddr_in *) socket_temp->addr_ptr)->sin_addr.s_addr);
            printf("** src_ip: %d\n", *src_ip);
            /* TODO Get peer address */
            uint32_t *dest_ip = &(socket_temp->peer_values->peer_addr_ptr->sin_addr.s_addr);

            /* send packet */
            CreatePacketHeader(packet, packet_header, src_ip, dest_ip, 20, NULL);
            this->sendPacket("IPv4", packet);
            socket_temp->seq_num = socket_temp->seq_num + (uint32_t) 1;

            /* change state to next state */
            StateMachine *state_machine = new StateMachine(socket_temp->state_label, socket_temp->socket_type);
            debug->Log(socket_temp->state_label);

            socket_temp->state_label = (Label) state_machine->Transit(Signal::CLOSE);
            debug->Log(socket_temp->state_label);
            socket_temp->syscallUUID = syscallUUID;
            socket_temp->send_fin = 1;
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
        struct sockaddr_in *sockaddr_ptr_new = (sockaddr_in *) sockaddr_ptr;
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
        socket_ptr_ret->addr_ptr = new sockaddr;
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
        debug->BigLog("syscall connect");
        Socket *cli_socket = new Socket;

        if (FindSocketWithFd(client_fd, cli_socket, socket_bucket) == -1) {
            // Socket not found.
            returnSystemCall(syscallUUID, -1);
        }

        if (cli_socket->is_bind == 0) {
            int interface_index;

            in_addr_t *ip_addr_dest_ptr = &(((sockaddr_in *) server_addr)->sin_addr.s_addr);
            in_addr_t *ip_addr_src_ptr = new in_addr_t;
            interface_index = getHost()->getRoutingTable((const uint8_t *) ip_addr_dest_ptr);
            getHost()->getIPAddr((uint8_t *) ip_addr_src_ptr, interface_index);

            sockaddr_in *cli_addr_ptr = new sockaddr_in;
            cli_addr_ptr->sin_family = AF_INET;
            cli_addr_ptr->sin_port = htons((uint16_t) 30000);
            cli_addr_ptr->sin_addr.s_addr = (u_long) ip_addr_src_ptr;

            cli_socket->addr_ptr = (struct sockaddr *) cli_addr_ptr;
            cli_socket->sock_len = *(&server_addr_length);
            cli_socket->seq_num = 0;
            cli_socket->ack_num = 0;

            cli_socket->is_bind = 1;
        }

        // TODO: set packet header & packet
        TCPHeader *packet_header = new TCPHeader;
        packet_header->src_port = ((sockaddr_in *) cli_socket->addr_ptr)->sin_port;
        packet_header->dest_port = ((sockaddr_in *) server_addr)->sin_port;
        packet_header->head_length = 0x50;
        packet_header->offset_res_flags = 0x02;
        packet_header->seq_num = cli_socket->seq_num;
        packet_header->ack_num = (uint16_t) 0;
        packet_header->checksum = (uint16_t) 0;
        packet_header->urgent_ptr = (uint16_t) 0;
        packet_header->window = (uint16_t) 0;

        Packet *packet = this->allocatePacket(54);

        uint32_t *src_ip = &(((sockaddr_in *) cli_socket->addr_ptr)->sin_addr.s_addr);
        uint32_t *dest_ip = &(((sockaddr_in *) server_addr)->sin_addr.s_addr);

        // TODO: send packet
        CreatePacketHeader(packet, packet_header, src_ip, dest_ip, 20, NULL);
        this->sendPacket("IPv4", packet);

        // TODO: change state to SYN_SENT
        cli_socket->state_label = Label::SYN_SENT;

        // TODO: change each states of socket.
        cli_socket->socket_type = MachineType::CLIENT;
        cli_socket->syscallUUID = syscallUUID;

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
        listen_value->syscallUUID = syscallUUID;

        RemoveSocketWithFd(server_fd, &socket_bucket);
        socket_bucket.sockets.push_back(socket_ptr);

        returnSystemCall(syscallUUID, 0);
    }

    void TCPAssignment::CreatePacketHeader(
            Packet *packet, E::TCPHeader *packet_header, uint32_t *src_ip, uint32_t *dest_ip,
            int length_TCPseg, char* data) {
        uint16_t *checksum_ = (uint16_t *) malloc(sizeof(uint16_t));
        *checksum_ = (uint16_t) 0;

        packet->writeData(14 + 12, src_ip, 4);
        packet->writeData(14 + 16, dest_ip, 4);

        packet->writeData(14 + 20, packet_header, 20);
        packet->writeData(14 + 20 + 20, data, length_TCPseg-20);

        /* Calculating Checksum */
        pseudoHeader *pseudoHeader_temp = new pseudoHeader;

        uint8_t *TCP_segment = (uint8_t *) malloc(length_TCPseg);
        /* Gathering TCP header and TCP data */
        memcpy(TCP_segment, packet_header, 20);
        memcpy(TCP_segment + 20, data, length_TCPseg - 20);

        pseudoHeader_temp->src_ip = *src_ip;
        pseudoHeader_temp->dest_ip = *dest_ip;
        pseudoHeader_temp->reserved = (uint8_t) 0;
        pseudoHeader_temp->protocol = (uint8_t) 6;
        pseudoHeader_temp->TCP_segment_length = htons((uint16_t) length_TCPseg);

        int total_length = 12 + length_TCPseg;
        uint8_t *total_structure = (uint8_t *) malloc(total_length);
        memcpy(total_structure, pseudoHeader_temp, 12);
        memcpy(total_structure + 12, TCP_segment, length_TCPseg);

        *checksum_ = checksum((unsigned short *) total_structure, total_length);
        packet->writeData(14 + 20 + 16, checksum_, 2);

        memcpy(total_structure + 12 + 16, checksum_, 2);
        uint16_t checksum_test = checksum((unsigned short *) total_structure, total_length);
        printf("** checksum retest: %d ** \n", checksum_test);

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

        CreatePacketHeader(packet, new_header, src_ip, dest_ip, length, NULL);
    }

    void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int listen_fd,
                                       struct sockaddr *client_addr, socklen_t *client_addr_len) {
        debug->BigLog("syscall accept");
        Socket *server_socket_ptr = new Socket;
        if (FindSocketWithFd(listen_fd, server_socket_ptr, socket_bucket) == -1) {
            debug->Log("No Socket");
            returnSystemCall(syscallUUID, -1);
        }

        block_value->syscallUUID = syscallUUID;

        // if socket has recent connection -> child
        if (server_socket_ptr->backlog_ready.size() > 0) {
            int fd = server_socket_ptr->backlog_ready[0];
            debug->Log("fd", fd);
            Socket *server_cli_socket_ptr = new Socket;
            int i = FindSocketWithFd(fd, server_cli_socket_ptr, socket_bucket);

            memcpy(client_addr, (struct sockaddr *) server_cli_socket_ptr->peer_values->peer_addr_ptr,
                   sizeof(server_cli_socket_ptr->peer_values->peer_addr_ptr));
            *client_addr_len = 16;

            server_socket_ptr->backlog_ready.erase(server_socket_ptr->backlog_ready.begin());

            RemoveSocketWithFd(listen_fd, &socket_bucket);
            socket_bucket.sockets.push_back(server_socket_ptr);
            block_value = new BlockValue;
            //            block_value->isCalled = 0;

            debug->StarLog("syscallUUID", (int) syscallUUID);
            returnSystemCall(syscallUUID, fd);
            return;
        }

        debug->Log("Has NO connection");

        RemoveSocketWithFd(listen_fd, &socket_bucket);
        socket_bucket.sockets.push_back(server_socket_ptr);

        block_value->fd = listen_fd;
        block_value->pid = pid;
        block_value->sockaddr_ptr = client_addr;
        block_value->socklen_ptr = client_addr_len;
        block_value->isCalled = 1;
    }

    void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int listen_fd,
                                            struct sockaddr *client_addr, socklen_t *client_addr_len) {
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
               (sockaddr *) cli_socket_ptr->peer_values->peer_addr_ptr,
               sizeof(cli_socket_ptr->peer_values->peer_addr_ptr));

        returnSystemCall(syscallUUID, 0);

    }

    void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void *write_content, int size_write){
        // TODO: find socket.
        debug->BigLog("syscall write");
        Socket *socket_ptr = new Socket;
        if (FindSocketWithFd(fd, socket_ptr, socket_bucket) == -1) {
            returnSystemCall(syscallUUID, ERR_BASIC); // You can delete this code if want to block in no-socket.
            return;
        }

        // TODO: check whether given data is larger then write max buffer.
        if (size_write > socket_ptr->writeBuffer->max_size) {
            debug->Log("write data is bigger than max buffer size");
            // TODO: YOU SHOULD BLOCK THIS VALUE
            return;
        }

        // TODO: check with cwnd & all packet size
        int sending_data_total = socket_ptr->writeBuffer->unack_size + size_write;
        if (sending_data_total > socket_ptr->writeBuffer->cwnd) {
            debug->Log("packet is bigger than sending window size");
            // TODO: YOU SHOULD BLOCK THIS VALUE
            return;
        }

        // TODO: set buffer write values. Get seq
        int last_index = socket_ptr->writeBuffer->packet_data_bucket.size() - 1;
        int last_seq;
        if (last_index == -1) {
            // there are no data in writeBuffer
            last_seq = socket_ptr->seq_num;
        } else {
            last_seq = socket_ptr->writeBuffer->packet_data_bucket[last_index]->seq_num;
        }

        debug->Log("last seq: ", last_seq);
        printf("** size write: %d\n", size_write);
        /* Temporary test */
        if (size_write < 0)
            return;
        // TODO: compare with max packet size.
        int max_packet_length = 1440;
        if (size_write > max_packet_length) {
            // TODO: logic for 'dividing' packet.
            int written_byte_num = 0;
            int packet_num = ((size_write - written_byte_num) / max_packet_length) + 1;

            for (int i = 0; i < packet_num; i++) {
                DataHolder *data_holder_ptr = new DataHolder;
                //			last_seq += size_write;
                //			data_holder_ptr->seq_num = last_seq;

                // 마지막 세트의 경우 패킷에 담을 데이터 사이즈가 쪼꼬미
                int cpy_size = max_packet_length;
                if ((size_write - written_byte_num) < max_packet_length) {
                    cpy_size = size_write - written_byte_num;
                }

                /* Set the variables in the data holder */
                last_seq += cpy_size;
                data_holder_ptr->seq_num = last_seq;
                data_holder_ptr->data_size = cpy_size;
                data_holder_ptr->data = (char *)malloc(sizeof(char) * cpy_size);
                memcpy(data_holder_ptr->data, (char *)write_content + written_byte_num, cpy_size);
                socket_ptr->writeBuffer->packet_data_bucket.push_back(data_holder_ptr);

                // iteration
                written_byte_num += cpy_size;
            }
        } else {
            // TODO: logic for 'unique' packet.
            DataHolder *data_holder_ptr = new DataHolder;
            last_seq += size_write;
            data_holder_ptr->seq_num = last_seq;
            data_holder_ptr->data_size = size_write;

            debug->Log("1");
            data_holder_ptr->data = (char *)malloc(size_write);
            memcpy(data_holder_ptr->data, write_content, size_write);
            debug->Log("2");

            socket_ptr->writeBuffer->packet_data_bucket.push_back(data_holder_ptr);
            debug->Log("3");

        }
        // TODO: set buffer's nonack value, and set all socket value in socket_bucket.
        socket_ptr->writeBuffer->unack_size -= size_write;
        socket_ptr->seq_num = socket_ptr->writeBuffer->packet_data_bucket[0]->seq_num;

        RemoveSocketWithFd(fd, &socket_bucket);
        socket_bucket.sockets.push_back(socket_ptr);
        int send_data = 0;

        // TODO: send packet. 우선은 혼잡에 대한 생각은 하지 말고, 해당 write데이터에 대한 것만.
        for (int i = 0; i < socket_ptr->writeBuffer->packet_data_bucket.size(); i++) {
            debug->Log("Send Packet!!");
            DataHolder *packet_data_ptr = socket_ptr->writeBuffer->packet_data_bucket[i];
            int packet_size = 54 + packet_data_ptr->data_size;
            send_data += packet_data_ptr->data_size;

            // allocate packet with computed packet size.
            Packet *packet = this->allocatePacket(packet_size);

            // set header
            TCPHeader *packet_header = new TCPHeader;
            packet_header->src_port = ((sockaddr_in *) socket_ptr->addr_ptr)->sin_port;
            packet_header->dest_port = socket_ptr->peer_values->peer_addr_ptr->sin_port;
            packet_header->offset_res_flags = 0x00;
            packet_header->head_length = 0x50;
            packet_header->window = htons(socket_ptr->readBuffer->rwnd);
            packet_header->seq_num = htonl(packet_data_ptr->seq_num);
            packet_header->ack_num = htonl(socket_ptr->ack_num);
            packet_header->checksum = (uint16_t) 0;

            // set ip
            uint32_t *src_ip = &(((sockaddr_in *) socket_ptr->addr_ptr)->sin_addr.s_addr);
            uint32_t *dest_ip = &(socket_ptr->peer_values->peer_addr_ptr->sin_addr.s_addr);

            CreatePacketHeader(packet, packet_header, src_ip, dest_ip,
                               20 + packet_data_ptr->data_size, packet_data_ptr->data);
            packet->writeData(2, &packet_size, 2);

            this->sendPacket("IPv4", packet);

            /* socket value changing */
            socket_ptr->writeBuffer->unack_size += packet_data_ptr->data_size;
            socket_ptr->writeBuffer->cwnd =
                    socket_ptr->writeBuffer->max_size - socket_ptr->writeBuffer->unack_size;
            socket_ptr->seq_num = socket_ptr->seq_num + (uint32_t) packet_data_ptr->data_size;
            RemoveSocketWithFd(fd, &socket_bucket);
            socket_bucket.sockets.push_back(socket_ptr);
        }

        returnSystemCall(syscallUUID, send_data);
    };

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
                this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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
                                          static_cast<socklen_t *>(param.param3_ptr));
                break;
            default:
                assert(0);
        }
    }

    void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {
        /* Extract the IP address and port number of source and destination from the recv pkt */
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
            /* PASS */
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
        if (!fin) {
            //            debug->LogDivider();
        }

        //        debug->Log(recv);

        StateMachine *state_machine = new StateMachine(dest_socket_ptr->state_label, dest_socket_ptr->socket_type);
        //        debug->Log(dest_socket_ptr->state_label);
        Signal send = state_machine->GetSendSignalAndSetNextNode(recv);

        /* Packet Creation */
        Packet *new_packet = this->clonePacket(packet);
        TCPHeader *new_header = new TCPHeader;

        /* Setting head len and flags */
        new_header->head_length = packet_header->head_length;
        new_header->dest_port = htons(ntohs(packet_header->src_port));
        new_header->src_port = htons(ntohs(packet_header->dest_port));
        new_header->ack_num = htonl(ntohl(packet_header->seq_num) + (uint32_t) 1);
        new_header->seq_num = htonl(dest_socket_ptr->seq_num);
        new_header->window = packet_header->window;
        new_header->checksum = (uint16_t) 0;
        new_header->urgent_ptr = (uint16_t) 0;

        /* If the socket is in TIME_WAIT, re-send the ACK to server */
        if (dest_socket_ptr->is_timewait == 1 && dest_socket_ptr->state_label == Label::TIME_WAIT) {
            //            debug->StarLog("resend ack to server");
            new_header->offset_res_flags = 0x10;
            CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20, NULL);
            this->sendPacket("IPv4", new_packet);
            dest_socket_ptr->seq_num = (dest_socket_ptr->seq_num) + (uint32_t) 1;
            RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
            socket_bucket.sockets.push_back(dest_socket_ptr);

            this->freePacket(packet);
            delete packet_header;
            delete new_header;
            return;
        }

        if (syn && dest_socket_ptr->socket_type == MachineType::SERVER &&
            dest_socket_ptr->backlog->not_established < dest_socket_ptr->max_backlog) {
            Connection *new_connection_ptr = new Connection;

            // Set new client address pointer;
            sockaddr_in *new_cli_addr_ptr = new sockaddr_in;
            new_cli_addr_ptr->sin_addr.s_addr = *src_ip;
            new_cli_addr_ptr->sin_family = AF_INET;
            new_cli_addr_ptr->sin_port = packet_header->src_port;

            // set client address pointer to new connection pointer
            new_connection_ptr->cli_addr_ptr = new_cli_addr_ptr;
            //            printf("%d: %d\n", new_connection_ptr->cli_addr_ptr->sin_addr.s_addr,
            //                   new_connection_ptr->cli_addr_ptr->sin_port);

            // set destination socket (a.k.a. server socket) new connection & raise unestablished one.
            dest_socket_ptr->backlog->connections.push_back(new_connection_ptr);
            dest_socket_ptr->backlog->not_established = dest_socket_ptr->backlog->not_established + 1;

            if (dest_socket_ptr->state_label == Label::LISTEN ||
                dest_socket_ptr->state_label == Label::SYN_RCVD) {
                new_header->offset_res_flags = 0x12;
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20, NULL);
                this->sendPacket("IPv4", new_packet);

                dest_socket_ptr->state_label = Label::SYN_RCVD;
                dest_socket_ptr->seq_num = (dest_socket_ptr->seq_num) + (uint32_t) 1;
                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                this->freePacket(packet);
                delete packet_header;
                delete new_header;
                return;
            }
        }

        /* Do appropriate action */
        if (dest_socket_ptr->socket_type == MachineType::SERVER) { /* if the machine is server */
            if (dest_socket_ptr->state_label == Label::SYN_RCVD && ack) {
                int flag = 0;
                Socket *established_socket_ptr = new Socket;
                if (flag == 0) {
                    // Create new file descriptor.
                    int fd = 0;
                    fd = createFileDescriptor(dest_socket_ptr->pid);

                    // Set socket values in established_socket_ptr
                    established_socket_ptr->fd = fd;
                    established_socket_ptr->addr_ptr = new sockaddr;

                    established_socket_ptr->protocol = dest_socket_ptr->protocol;
                    established_socket_ptr->state_label = Label::ESTABLISHED;
                    established_socket_ptr->domain = dest_socket_ptr->domain;
                    established_socket_ptr->type = dest_socket_ptr->type;
                    established_socket_ptr->socket_type = MachineType::SERVER_CLIENT;
                    established_socket_ptr->sock_len = dest_socket_ptr->sock_len;

                    established_socket_ptr->seq_num = dest_socket_ptr->seq_num;
                    established_socket_ptr->ack_num = (uint32_t) 0;
                    established_socket_ptr->syscallUUID = dest_socket_ptr->syscallUUID;

                    memcpy(&(((sockaddr_in *) established_socket_ptr->addr_ptr)->sin_addr.s_addr),
                           dest_ip, sizeof(uint32_t));
                    memcpy(&(((sockaddr_in *) established_socket_ptr->addr_ptr)->sin_port),
                           &(packet_header->dest_port), sizeof(packet_header->dest_port));
                    ((sockaddr_in * )(established_socket_ptr->addr_ptr))->sin_family = AF_INET;

                    // Set peer value
                    Socket *peer_cli_ptr = new Socket;

                    FindParentSocketWithPort(packet_header->src_port, peer_cli_ptr, socket_bucket);
                    established_socket_ptr->peer_values->peer_fd = peer_cli_ptr->fd;
                    established_socket_ptr->peer_values->peer_addr_ptr = new sockaddr_in;
                    memcpy(&(established_socket_ptr->peer_values->peer_addr_ptr->sin_addr.s_addr),
                           src_ip, sizeof(uint32_t));
                    memcpy(&(established_socket_ptr->peer_values->peer_addr_ptr->sin_port),
                           &(packet_header->src_port), sizeof(uint16_t));
                    established_socket_ptr->peer_values->peer_addr_ptr->sin_family = AF_INET;

                    socket_bucket.sockets.push_back(established_socket_ptr);
                }

                // Set ready_backlog for further accept.
                RemoveConnectionWithIp(*src_ip, dest_socket_ptr->backlog);
                dest_socket_ptr->backlog_ready.push_back(established_socket_ptr->fd);
                dest_socket_ptr->backlog->not_established = dest_socket_ptr->backlog->not_established - 1;

                dest_socket_ptr->cli_sockets.push_back(established_socket_ptr->fd);
                dest_socket_ptr->state_label = Label::LISTEN;
                dest_socket_ptr->syscallUUID = listen_value->syscallUUID;

                if (dest_socket_ptr->backlog->not_established > 0 &&
                    dest_socket_ptr->backlog->not_established <= dest_socket_ptr->max_backlog) {
                    debug->StarLog("Picking out Packet....");
                    Connection *connection = dest_socket_ptr->backlog->connections[0]; // First connection
                    //                    dest_socket_ptr->backlog->connections.erase(
                    //                            dest_socket_ptr->backlog->connections.begin());
                    //                    dest_socket_ptr->backlog->not_established =
                    //                            dest_socket_ptr->backlog->not_established - 1;
                    Packet *new_new_packet = this->clonePacket(packet);

                    // Set header
                    new_header->dest_port = connection->cli_addr_ptr->sin_port;
                    new_header->seq_num = ntohl(connection->seq_num);
                    new_header->ack_num = ntohl(connection->ack_num + 1);
                    new_header->offset_res_flags = 0x12; // syn ack

                    CreatePacketHeader(new_new_packet, new_header, dest_ip,
                                       &(connection->cli_addr_ptr->sin_addr.s_addr), 20, NULL);

                    // Set state to SYN_RECEIVED again
                    dest_socket_ptr->state_label = Label::SYN_RCVD;
                    dest_socket_ptr->seq_num = dest_socket_ptr->seq_num + (uint32_t) 1;

                    // Set syscallUUID
                    dest_socket_ptr->syscallUUID = listen_value->syscallUUID;

                    // Send packet.
                    this->sendPacket("IPv4", new_new_packet);
                }
                this->freePacket(packet);
                this->freePacket(new_packet);

                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);
                delete new_header;
                delete packet_header;

                if (block_value->isCalled == 0) {
                    //                    printf("NOT\n");
                    // accept is not yet called.
                    returnSystemCall(established_socket_ptr->syscallUUID, 0);
                } else {
                    // 함수를 다시 불러보쟈...
                    this->syscall_accept(
                            block_value->syscallUUID,
                            block_value->pid,
                            block_value->fd,
                            block_value->sockaddr_ptr,
                            block_value->socklen_ptr);
                }
            } else if (dest_socket_ptr->state_label == Label::LISTEN && fin) { /* parent server socket recv fin */
                /* Find the child socket which belongs to parent socket */
                //                printf("** Parent recv fin **\n");
                Socket *child_socket_ptr = new Socket;
                if (FindChildSocketWithPorts(packet_header->dest_port, *src_ip, child_socket_ptr,
                                             socket_bucket) == -1) {
                    //                    printf("** cannot find child in recv fin **\n");
                    this->freePacket(packet);
                    this->freePacket(new_packet);
                    delete packet_header;
                    delete new_header;
                    return;
                    return;
                }

                //                debug->Log(child_socket_ptr->state_label);

                printf("** Child recv fin **\n");
                new_header->offset_res_flags = 0x10;
                new_header->seq_num = ntohl(child_socket_ptr->seq_num);
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20, NULL);
                this->sendPacket("IPv4", new_packet);

                //                debug->Log(child_socket_ptr->state_label);
                child_socket_ptr->state_label = Label::CLOSE_WAIT;
                //                debug->Log(child_socket_ptr->state_label);
                child_socket_ptr->seq_num = (child_socket_ptr->seq_num) + (uint32_t) 1;
                child_socket_ptr->close_fin = 1;

                RemoveSocketWithFd(child_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(child_socket_ptr);

                int remove_fd = 0;
                if (child_socket_ptr->close_ack == 1 &&
                    child_socket_ptr->close_fin == 1) { /* If the child recv both fin and ack from peer  */
                    remove_fd = child_socket_ptr->fd;
                    removeFileDescriptor(child_socket_ptr->pid, child_socket_ptr->fd);
                    RemoveSocketWithFd(child_socket_ptr->fd, &socket_bucket);
                    if (FindSocketWithFd(remove_fd, child_socket_ptr, socket_bucket) == -1)
                        printf("** server socket Remove success **\n ");
                }

                this->freePacket(packet);
                delete packet_header;
                delete new_header;
                return;
            } else if (dest_socket_ptr->state_label == Label::LISTEN && ack) {
                /* Find the child socket which belongs to parent socket */
                //                printf("** Parent recv ack **\n");
                Socket *child_socket_ptr = new Socket;
                if (FindChildSocketWithPorts(packet_header->dest_port, *src_ip, child_socket_ptr,
                                             socket_bucket) == -1) {
                    //                    printf("** cannot find child in recv ack **\n");
                    this->freePacket(packet);
                    this->freePacket(new_packet);
                    delete packet_header;
                    delete new_header;
                    return;
                };

                if (child_socket_ptr->send_fin == 1)
                    child_socket_ptr->close_ack = 1;
                RemoveSocketWithFd(child_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(child_socket_ptr);

                int remove_fd = 0;
                if (child_socket_ptr->close_ack == 1 &&
                    child_socket_ptr->close_fin == 1) { /* If the child recv both fin and ack from peer  */
                    //                    printf("** Child recv ack **\n");
                    remove_fd = child_socket_ptr->fd;
                    removeFileDescriptor(child_socket_ptr->pid, child_socket_ptr->fd);
                    RemoveSocketWithFd(child_socket_ptr->fd, &socket_bucket);
                    if (FindSocketWithFd(remove_fd, child_socket_ptr, socket_bucket) == -1)
                        printf("** server socket Remove success **\n ");
                }

                this->freePacket(new_packet);
                this->freePacket(packet);
                delete packet_header;
                delete new_header;
                return;
            } else {
                this->freePacket(packet);
                this->freePacket(new_packet);
                delete packet_header;
                delete new_header;
                return;
            }
        } else { /* if the machine is Client */
            if (dest_socket_ptr->state_label == Label::SYN_SENT && syn && ack) {
                // Final shake of Handshaking
                dest_socket_ptr->state_label = Label::ESTABLISHED;

                // Set peer values
                sockaddr_in *new_addr_ptr = new sockaddr_in;
                new_addr_ptr->sin_family = AF_INET;
                new_addr_ptr->sin_addr.s_addr = *src_ip;
                new_addr_ptr->sin_port = packet_header->src_port;

                dest_socket_ptr->peer_values->peer_addr_ptr = new_addr_ptr;

                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                // Send Packet
                new_header->offset_res_flags = 0x10;
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20, NULL);
                this->sendPacket("IPv4", new_packet);

                this->freePacket(packet);
                delete packet_header;
                delete new_header;

                returnSystemCall(dest_socket_ptr->syscallUUID, 0);
            } else if ((dest_socket_ptr->state_label == Label::FIN_WAIT_1 && fin) ||
                       (dest_socket_ptr->state_label == Label::FIN_WAIT_2 && fin) ||
                       (dest_socket_ptr->state_label == Label::FIN_WAIT_1 && fin && ack)) {
                new_header->offset_res_flags = 0x10;
                CreatePacketHeader(new_packet, new_header, dest_ip, src_ip, 20, NULL);
                this->sendPacket("IPv4", new_packet);

                dest_socket_ptr->state_label = (Label) state_machine->Transit(recv);
                dest_socket_ptr->seq_num = (dest_socket_ptr->seq_num) + (uint32_t) 1;
                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                this->freePacket(packet);
                delete packet_header;
                delete new_header;
            } else if ((dest_socket_ptr->state_label == Label::FIN_WAIT_1 && ack) ||
                       (dest_socket_ptr->state_label == Label::CLOSING && ack)) {
                dest_socket_ptr->state_label = (Label) state_machine->Transit(recv);
                RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
                socket_bucket.sockets.push_back(dest_socket_ptr);

                this->freePacket(packet);
                this->freePacket(new_packet);
                delete packet_header;
                delete new_header;
            } else {
                this->freePacket(packet);
                this->freePacket(new_packet);
                delete packet_header;
                delete new_header;
                return;
            }
        }

        if (dest_socket_ptr->state_label == Label::TIME_WAIT && dest_socket_ptr->is_timewait == 0) {
            /* socket is closed */
            //            debug->StarLog("Timer Set");
            Socket *socket_temp = new Socket;
            removeFileDescriptor(dest_socket_ptr->pid, dest_socket_ptr->fd);
            /* change the socket state: after timer on */
            dest_socket_ptr->is_timewait = 1;
            RemoveSocketWithFd(dest_socket_ptr->fd, &socket_bucket);
            socket_bucket.sockets.push_back(dest_socket_ptr);
            if (FindSocketWithFd(dest_socket_ptr->fd, socket_temp, socket_bucket) != -1)
                //                printf("** client socket Remove waiting **\n ");
                /* Start Timer: waiting for 60 seconds */
                addTimer(dest_socket_ptr, 60);
        }


    }

    void TCPAssignment::timerCallback(void *payload) {
        debug->BigLog("TIMER callback");
        Socket *socket_temp = (Socket *) payload;
        cancelTimer(socket_temp->syscallUUID);
        RemoveSocketWithFd(socket_temp->fd, &socket_bucket);
        if (FindSocketWithFd(socket_temp->fd, socket_temp, socket_bucket) == -1)
            printf("** client socket Remove success **\n ");
    }

/* The reference for the checksum:  http://locklessinc.com/articles/tcp_checksum/
 * @ Name: checksum
 * @ Function: Allow us to calculate TCP checksum */
    unsigned short TCPAssignment::checksum(unsigned short *ptr_packet, int size_packet) {
        register long c_sum;
        unsigned short oddbyte;
        register short c_sum_final;

        unsigned short *new_packet = ptr_packet;
        //        unsigned short* new_packet_ptr = new_packet;
        //        memcpy(new_packet, ptr_packet, size_packet);
        c_sum = 0;

        /* In calculating checksum, we should deal with the odd number byte.
         * While loop calculate the pre-checksum w.o. considering odd number byte.*/
        while (size_packet > 1) {
            c_sum += *new_packet++;
            size_packet -= 2;
        }

        /* Following if statement allows to cope with the 'odd case'.  */
        if (size_packet == 1) {
            oddbyte = 0;
            *((u_char * ) & oddbyte) = *(u_char *) new_packet;
            c_sum += oddbyte;
        }

        c_sum = (c_sum >> 16) + (c_sum & 0xffff);
        c_sum = c_sum + (c_sum >> 16);
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
        return (int) current_node;
    }

    int TCPAssignment::FindDataIndexWithSeq(int seq_num, E::WriteBuffer *write_buffer) {
        // Find data index with seq num.
        for (int i = 0; i < write_buffer->packet_data_bucket.size(); i++) {
            DataHolder *data_holder = write_buffer->packet_data_bucket[i];
            if (data_holder->seq_num == seq_num) {
                return i;
            }
        }
        return ERR_BASIC;
    }

    int TCPAssignment::DeleteDataWithIndex(int index, E::WriteBuffer *write_buffer) {
        if (write_buffer->packet_data_bucket.size() < index) {
            return ERR_BASIC;
        }
        int size;
        for (int i = 0; i < index + 1; i++) {
            size += write_buffer->packet_data_bucket[i]->data_size;
        }
        write_buffer->packet_data_bucket.erase(
                write_buffer->packet_data_bucket.begin(),
                write_buffer->packet_data_bucket.begin() + index);
        return size;
    }

    int TCPAssignment::DeleteDataWithSeq(int seq_num, E::WriteBuffer *write_buffer) {
        int index = FindDataIndexWithSeq(seq_num, write_buffer);
        if (index >= 0) {
            int size = DeleteDataWithIndex(index, write_buffer);
            write_buffer->unack_size = write_buffer->unack_size + size;
            return size;
        } else {
            return index;
        }

    }

/**
 * 저거 위에 있는 DeleteDataWithIndex처럼 똑같이하면될걸?
 * @param index 이만큼
 * @param read_buffer 여기에서 지워주세요.
 * @return
 */
    int DeleteDataWithLen(int index, ReadBuffer *read_buffer) {
        if (read_buffer->packet_data_bucket.size() < index)
            return -1;
        else
            read_buffer->packet_data_bucket.erase(read_buffer->packet_data_bucket.begin(),
                                                  read_buffer->packet_data_bucket.begin() + index);

        return 1;
    }


/**
 * safe coding 필요함. 맥스 사이즈에서 알아서 뺴서 섹폴 안나게
 * 읽은 만큼 없애야됨!!!!!!!!!!!!!
 *  *** 여기서 len이 더 긴 경우 다 읽으면 됨.
 * @param data_ret 여기다가
 * @param len 요만큼
 * @param read_buffer 여기서 읽어서 복사하세요. 아마 memcpy로 하는 게 복장터지지않을듯
 * @return -1 에러면
 */
    int ReadDataWithLen(char *data_ret, int len, ReadBuffer *read_buffer) {
        int total_dataHolder_length = read_buffer->packet_data_bucket.size();
        /* data_ret_index: to identify the location of the data in the data_ret */
        int data_ret_index = 0;
        int delete_index = 0;
        int max_size = read_buffer->max_size;
        int rwnd = read_buffer->rwnd;

        /* max_size - rwnd = allocated size in read Buffer */
        /* If a len is larger than total data holder length, just read all from the buffer */
        if (len >= max_size - rwnd) {
            data_ret = (char *) malloc(max_size - rwnd);
            for (int i = 0; i < total_dataHolder_length; i++) {
                memcpy(data_ret + data_ret_index, read_buffer->packet_data_bucket[i]->data,
                       read_buffer->packet_data_bucket[i]->data_size);
                data_ret_index += read_buffer->packet_data_bucket[i]->data_size;
                delete_index++;
            }
            if (DeleteDataWithLen(delete_index, read_buffer) == -1)
                return -1;
            return 1;
        } else {
            data_ret = (char *) malloc(len);
            int read_size = 0;
            for (int i = 0; len >= read_size;) {
                memcpy(data_ret + data_ret_index, read_buffer->packet_data_bucket[i]->data,
                       read_buffer->packet_data_bucket[i]->data_size);
                data_ret_index += read_buffer->packet_data_bucket[i]->data_size;
                read_size += read_buffer->packet_data_bucket[i]->data_size;
                delete_index++;
            }
            if (DeleteDataWithLen(delete_index, read_buffer) == -1)
                return -1;
            return 1;
        }
    }

}
			