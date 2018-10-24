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

/**
 * STATIC VARIABLES
 */
    StateNode *node_closed = new StateNode(Label::CLOSED, "Closed");
    StateNode *node_syn_sent = new StateNode(Label::SYN_SENT, "Syn Sent");
    StateNode *node_established = new StateNode(Label::ESTABLISHED, "Established");
    StateNode *node_fin_wait_1 = new StateNode(Label::FIN_WAIT_1, "Fin Wait 1");
    StateNode *node_fin_wait_2 = new StateNode(Label::FIN_WAIT_2, "Fin Wait 2");
    StateNode *node_closing = new StateNode(Label::CLOSING, "Closing");
    StateNode *node_time_wait = new StateNode(Label::TIME_WAIT, "Time Wait");
    StateNode *node_listen = new StateNode(Label::LISTEN, "Listen");
    StateNode *node_syn_rcvd = new StateNode(Label::SYN_RCVD, "Syn Received");
    StateNode *node_close_wait = new StateNode(Label::CLOSE_WAIT, "Close Wait");
    StateNode *node_last_ack = new StateNode(Label::LAST_ACK, "Last Ack");
    StateNode *node_none = new StateNode(Label::NONE, "None");

    StateNode *state_label_table[12] = {
            node_closed, node_listen, node_syn_rcvd,
            node_syn_sent, node_established, node_close_wait,
            node_last_ack, node_fin_wait_1, node_closing,
            node_fin_wait_2, node_time_wait, node_none
    };

    StateLink *link_none = new StateLink(node_none, node_none, Signal::NONE, Signal::NONE);

// For client
    StateLink *link_closed_to_syn_sent = new StateLink(node_closed, node_syn_sent, Signal::OPEN, Signal::SYN);
    StateLink *cli_closed_table[3] = {
            link_closed_to_syn_sent, link_none, link_none};

    StateLink *link_syn_sent_to_established =
            new StateLink(node_syn_sent, node_established, Signal::SYN_ACK, Signal::ACK);
    StateLink *link_syn_sent_to_closed = new StateLink(node_syn_sent, node_closed, Signal::ERR, Signal::NONE);
    StateLink *link_syn_sent_to_closed2 = new StateLink(node_syn_sent, node_closed, Signal::CLOSE, Signal::NONE);
    StateLink *cli_syn_sent_table[3] = {
            link_syn_sent_to_established,
            link_syn_sent_to_closed,
            link_syn_sent_to_closed2
    };

    StateLink *link_established_to_fin_wait_1 =
            new StateLink(node_established, node_fin_wait_1, Signal::CLOSE, Signal::FIN);
    StateLink *cli_established_table[3] = {
            link_established_to_fin_wait_1, link_none, link_none};

    StateLink *link_fin_wait_1_to_closing = new StateLink(node_fin_wait_1, node_closing, Signal::FIN, Signal::ACK);
    StateLink *link_fin_wait_1_to_time_wait =
            new StateLink(node_fin_wait_1, node_time_wait, Signal::FIN_ACK, Signal::ACK);
    StateLink *link_fin_wait_1_to_fin_wait_2 =
            new StateLink(node_fin_wait_1, node_fin_wait_2, Signal::ACK, Signal::NONE);
    StateLink *cli_fin_wait_1_table[3] = {
            link_fin_wait_1_to_closing,
            link_fin_wait_1_to_fin_wait_2,
            link_fin_wait_1_to_time_wait
    };

    StateLink *link_closing_to_time_wait = new StateLink(node_closing, node_time_wait, Signal::ACK, Signal::NONE);
    StateLink *cli_closing_table[3] = {
            link_closing_to_time_wait, link_none, link_none
    };

    StateLink *link_fin_wait_2_to_time_wait = new StateLink(node_fin_wait_2, node_time_wait, Signal::FIN, Signal::ACK);
    StateLink *cli_fin_wait_2_table[3] = {
            link_fin_wait_2_to_time_wait, link_none, link_none};

    StateLink *link_time_wait_to_closed = new StateLink(node_time_wait, node_closed, Signal::ERR, Signal::NONE);
    StateLink *cli_time_wait_table[3] = {
            link_time_wait_to_closed, link_none, link_none};

// For server
    StateLink *link_closed_to_listen = new StateLink(node_closed, node_listen, Signal::OPEN, Signal::NONE);
    StateLink *serv_closed_table[3] = {
            link_closed_to_listen, link_none, link_none};

    StateLink *link_listen_to_syn_rcvd = new StateLink(node_listen, node_syn_rcvd, Signal::SYN, Signal::SYN_ACK);
    StateLink *serv_listen_table[3] = {
            link_listen_to_syn_rcvd, link_none, link_none};

    StateLink *link_syn_rcvd_to_closed = new StateLink(node_syn_rcvd, node_closed, Signal::ERR, Signal::NONE);
    StateLink *link_syn_rcvd_to_established = new StateLink(node_syn_rcvd, node_established, Signal::ACK, Signal::NONE);
    StateLink *serv_syn_rcvd_table[3] = {
            link_syn_rcvd_to_closed,
            link_syn_rcvd_to_established,
            link_none
    };

    StateLink *link_established_to_close_wait =
            new StateLink(node_established, node_close_wait, Signal::FIN, Signal::ACK);
    StateLink *serv_established_table[3] = {
            link_established_to_close_wait, link_none, link_none};

    StateLink *link_close_wait_to_last_ack = new StateLink(node_close_wait, node_last_ack, Signal::CLOSE, Signal::ACK);
    StateLink *serv_close_wait_table[3] = {
            link_close_wait_to_last_ack, link_none, link_none};

    StateLink *link_last_ack_to_closed = new StateLink(node_last_ack, node_closed, Signal::ACK, Signal::NONE);
    StateLink *serv_last_ack_table[3] = {
            link_last_ack_to_closed, link_none, link_none};

    StateLink **cli_link_table[7] = {
            cli_closed_table, cli_syn_sent_table, cli_established_table,
            cli_fin_wait_1_table, cli_fin_wait_2_table, cli_closing_table,
            cli_time_wait_table
    };

    StateLink **serv_link_table[6] = {
            serv_closed_table, serv_listen_table, serv_syn_rcvd_table,
            serv_established_table, serv_close_wait_table, serv_last_ack_table
    };

    Label cli_label_table[7] = {
            Label::CLOSED, Label::SYN_SENT, Label::ESTABLISHED,
            Label::FIN_WAIT_1, Label::FIN_WAIT_2, Label::CLOSING,
            Label::TIME_WAIT
    };

    Label serv_label_table[6] = {
            Label::CLOSED, Label::LISTEN, Label::SYN_RCVD,
            Label::ESTABLISHED, Label::CLOSE_WAIT, Label::LAST_ACK
    };

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
        //        StateMachineWrap state_machine_wrap;
        //        state_machine_wrap.stateMachine = *(new StateMachine());
        //        state_machine_wrap.fd = fd;
        //        state_machine_b.PushBack(state_machine_wrap);

        returnSystemCall(syscallUUID, fd);
    }

    void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
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
            struct sockaddr *param2_ptr, socklen_t *param3_ptr) {
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
    }

    void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *sockaddr_ptr,
                                     socklen_t sock_len) {
        struct sockaddr sockaddr_imsi = *sockaddr_ptr;

        int ret = socket_b.bind_socket_by_fd(fd, &sockaddr_imsi, sock_len);

        returnSystemCall(syscallUUID, ret);
    }

    void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int client_fd,
                                        struct sockaddr *server_addr, socklen_t server_addr_length) {
        /* Set client addr and port number(= implicit bound),
         * if addr and port have not been set before.
         */
        struct socket *client_socket;
        socket_b.get_socket_by_fd(client_fd, client_socket);

        if ( client_socket->clientaddr_defined == 0 ) { // Client socket addr is not set.
            client_socket->addr_ptr = (struct sockaddr*) malloc(sizeof(struct sockaddr));
            uint32_t ip_addr_dest[1];
            uint32_t ip_addr_src[1];
            *(ip_addr_dest) = ((struct sockaddr_in*) server_addr)->sin_addr.s_addr;

            int interface_index;
            interface_index = getHost()->getRoutingTable((uint8_t*)ip_addr_dest);
            getHost()->getIPAddr((uint8_t*)ip_addr_src, interface_index);

            struct sockaddr_in *temp_addr_ptr = (sockaddr_in *) malloc (sizeof(sockaddr_in *));
            temp_addr_ptr->sin_family = AF_INET;
            temp_addr_ptr->sin_port = htons( (uint16_t) 30000 ); /* Port in Network Byte */
            temp_addr_ptr->sin_addr.s_addr = (u_long) ip_addr_src;
            client_socket->addr_ptr = (struct sockaddr *)temp_addr_ptr;

            client_socket->clientaddr_defined = 1;
        }
        /* Send SYN bit to the server. */
        Packet* packet_start;
        packet_start = this->allocatePacket(54);

        uint32_t src_ip[1];
        uint32_t dest_ip[1];
        uint16_t src_port[1];
        uint16_t dest_port[1];
        /* Set addr_ptr of the client socket */
        /*
                    (struct sockaddr_in *)(client_socket.addr_ptr)->sin_family = AF_INET;
                    (struct sockaddr_in *)(client_socket.addr_ptr)->sin_port = (uint16_t) 3000;
                    (struct sockaddr_in *)(client_socket.addr_ptr)->sin_addr = (struct in_addr)(*(ip_addr_src)); */

        *(src_ip) = ((struct sockaddr_in *)client_socket->addr_ptr)->sin_addr.s_addr; // 네 번 값 받기.
        *(dest_ip) = ((struct sockaddr_in *)server_addr)->sin_addr.s_addr;
        *(src_port) = ((struct sockaddr_in *)client_socket->addr_ptr)->sin_port;
        *(dest_port) = ((struct sockaddr_in *)server_addr)->sin_port;;

        uint32_t SEQ_num_send[1];
        SEQ_num_send[0] = htonl(client_socket->SEQ_num);
        uint32_t ACK_num_send[1];
        ACK_num_send[0] = htonl((uint32_t) 0);

        uint8_t all_flags_send[1];
        all_flags_send[0] = 0x02;

        createPacketHeader(packet_start, src_ip, dest_ip, src_port, dest_port, SEQ_num_send
                , ACK_num_send, all_flags_send);

        /* Save the syscallUUID to return */
        client_socket->syscallUUID = &syscallUUID;

        /* Change the state of the socket to listen */
        client_socket->state_machine_ptr = (StateMachine*)malloc(sizeof(StateMachine));
        client_socket->state_machine_ptr = new StateMachine(MachineType::CLIENT);
        StateMachine *client_state_machine = static_cast<StateMachine *> (client_socket->state_machine_ptr);
        client_state_machine->transit(Signal::OPEN);

        socket_b.delete_socket(client_fd);
        socket_b.put_socket(client_fd, *(client_socket));

        this->sendPacket("IPv4", packet_start);

    }

    void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int server_fd, int max_backlog) {
        /* TODO: Error Detection
         * Is this socket bound before?
         */
        struct socket *server_socket;
        server_socket = (struct socket*) malloc(sizeof(struct socket));
        socket_b.get_socket_by_fd(server_fd, server_socket);
        server_socket->state_machine_ptr = (StateMachine*)malloc( sizeof(StateMachine) );
        server_socket->state_machine_ptr = new StateMachine(MachineType::SERVER);
        StateMachine *server_state_machine = static_cast<StateMachine *> (server_socket->state_machine_ptr);
        server_state_machine->transit(Signal::OPEN);

        server_socket->max_backlog = max_backlog;
        server_socket->current_backlog = 0;
        server_socket->backlog_table = (struct sockaddr **)malloc(sizeof(struct sockaddr *));

        /* Listen Check point */
        /*
        printf("=== Listen: server_state_machine ptr: %p === \n",
                server_state_machine);
        printf("=== Listen: server_socket->state_machine_ptr: %p === \n",
                server_socket->state_machine_ptr);
        printf("=== Listen: server_socket->SEQ_num: %d === \n", server_socket->SEQ_num); */

        socket_b.delete_socket(server_fd);
        socket_b.put_socket(server_fd, *(server_socket));
        /* TODO
         * Set server_fd to 'listen' the connection request.
         */

        /* TODO
         * Set the max_backlog of the server_fd
         */
        int ret = 0;
        returnSystemCall(syscallUUID, ret);
    }

    void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int listen_fd,
                                       struct sockaddr *client_addr, socklen_t *client_addr_len) {

        /* TODO: Error detection
         * Is this server socket bound before?
         * Is this server socket set as listen?
         */

        printf("Accept FUnction!\n");
        struct socket *server_socket;
        struct socket *client_socket;

        server_socket = (struct socket*) malloc(sizeof(struct socket));
        socket_b.get_socket_by_fd(listen_fd, server_socket);
        StateMachine *serv_state_machine = (StateMachine *)server_socket->state_machine_ptr;
        serv_state_machine->log();

        if (serv_state_machine->GetCurrentState()->GetLabel() == Label::ESTABLISHED) {
            // there is connection!
            int client_fd = createFileDescriptor(pid);
            printf("fd: %d\n", client_fd);

            client_socket.domain = param1_int;
            client_socket.type = param2_int;
            client_socket.protocol = IPPROTO_TCP;
            client_socket.sock_len = 0;
            client_socket->state_machine_ptr =
                    new StateMachine(MachineType::CLIENT);
            client_socket->state_machine_ptr

            socket_b.put_socket(fd, client_socket);
            //        StateMachineWrap state_machine_wrap;
            //        state_machine_wrap.stateMachine = *(new StateMachine());
            //        state_machine_wrap.fd = fd;
            //        state_machine_b.PushBack(state_machine_wrap);

//            returnSystemCall(syscallUUID, fd);
        }

        int * error_detection = (int *) malloc (sizeof(int));



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
        int ret = 5;
        returnSystemCall(syscallUUID, ret);
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
                //this->syscall_getpeername(syscallUUID, pid, param.param1_int,
                //      static_cast<struct sockaddr *>(param.param2_ptr),
                //      static_cast<socklen_t*>(param.param3_ptr));
                break;
            default:
                assert(0);
        }
    }

    void TCPAssignment::packetArrived(std::string fromModule, Packet *packet) {
        /* Extract the IP address and port number of source and destination from the recv pkt */
        /* Extract the IP address and port number of source and destination from the recv pkt */
        uint32_t src_ip[1];
        uint32_t dest_ip[1];
        uint16_t src_port[1];
        uint16_t dest_port[1];
        int should_send_data = 1;

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
        int ACK_recv, SYN_recv, FIN_recv;
        int ACK_send, SYN_send, FIN_send;

        packet->readData(14+20+13, all_flags_recv, 1);
        all_flags_send[0] = *all_flags_recv; /* copy recv packet flags */

        ACK_recv = ( (all_flags_recv[0] & 0x10) == 0 )? 0:1;
        SYN_recv = ( (all_flags_recv[0] & 0x02) == 0 )? 0:1;
        /* TODO Fin bit must be received from the recv packet */
        FIN_recv = 0;

        /* Read ACK num and SEQ num from pkt. */
        uint32_t ACK_num_recv_n[1];
        uint32_t SEQ_num_recv_n[1];
        uint32_t ACK_num_recv_h;
        uint32_t SEQ_num_recv_h;
        uint32_t ACK_num_send[1];
        uint32_t SEQ_num_send[1];

        packet->readData(14+20+4, SEQ_num_recv_n, 4);
        packet->readData(14+20+8, ACK_num_recv_n, 4);

        ACK_num_recv_h = ntohl(ACK_num_recv_n[0]);
        SEQ_num_recv_h = ntohl(SEQ_num_recv_n[0]);

        /* TODO Set the target socket according to the dest_ip and dest_port */
        /* Extract data from the dest_port to the dest_port_Data */
        struct socket *socket_target;
        file file_target;
        int * error_detection =(int*)malloc(sizeof(int));
        *(error_detection) = 0;

        file_target = socket_b.get_file_by_port((unsigned short)(*dest_port), error_detection);
        if( *error_detection )
            return;
        socket_target = &(file_target.socket);
        free(error_detection);

        /* Check the ACK num */
        //   if ( *(ACK_num_recv) != (file_target.SEQ_num) ) /* Not in-order packet */
        //      return;

        /* 1. Change bitwise flag signal to Signal type signal. */
        Signal recv_signal;
        if ( ACK_recv && SYN_recv ){
            printf("=== packet: RECV SYN_ACK ===\n");
            recv_signal = Signal::SYN_ACK;
        }
        else if ( ACK_recv && FIN_recv ){
            printf("=== packet: RECV FIN_ACK===\n");
            recv_signal = Signal::FIN_ACK;
        }
        else if ( ACK_recv ){
            printf("=== packet: RECV ACK ===\n");
            recv_signal = Signal::ACK;
        }
        else if ( SYN_recv ){
            printf("=== packet: RECV SYN ===\n");
            recv_signal = Signal::SYN;
        }
        else if ( FIN_recv ){
            printf("=== packet: RECV FIN ===\n");
            recv_signal = Signal::FIN;
        }
        else{
            printf("=== packet: RECV ERR ===\n");
            recv_signal = Signal::ERR;
        }

        /* Recv the signal to send to the sender */
        StateMachine* state_machine_socket = static_cast<StateMachine*> (socket_target->state_machine_ptr);
        //	printf("===== socket_target SEQ_num: %d, state_machine_socket: %p ==== \n",
        //			socket_target->SEQ_num, state_machine_socket);
        Signal send_signal = state_machine_socket->GetSendSignal(recv_signal);
        printf("Signal: %d\n", send_signal);

        ACK_send = 0;
        SYN_send = 0;
        FIN_send = 0;
        if ( send_signal == Signal::SYN_ACK ){
            printf("=== SEND SYN_ACK === \n");
            ACK_send = 1;
            SYN_send = 1;
        }
        else if ( send_signal == Signal::FIN_ACK){
            printf("=== SEND FIN_ACK === \n");
            ACK_send = 1;
            FIN_send = 1;
        }
        else if ( send_signal == Signal::SYN){
            printf("=== SEND SYN === \n");
            SYN_send = 1;
        }
        else if ( send_signal == Signal::ACK){
            printf("=== SEND ACK === \n");
            ACK_send = 1;
        }
        else if ( send_signal == Signal::FIN){
            printf("=== SEND FIN=== \n");
            FIN_send = 1;
        }/* If Signal type is NONE, do not send anything to the parter */
        else if ( send_signal == Signal::NONE){
            printf("=== DO NOT SEND ===\n");
            should_send_data = 0;
        } else if ( send_signal == Signal::ERR) {
            printf("=== DO NOT SEND ===\n");
            should_send_data = 0;
        }

        if ( should_send_data ){ /* If Signal is not NONE */
            /* Create packet */
            printf("======= Let's send a packet! =======\n");
            Packet *packet_send;
            packet_send = this->clonePacket(packet);

            /* Set Packet */
            /* ACK bit and SYN bit */
            uint8_t flags_send_temp = 0x00;
            flags_send_temp = all_flags_send[0] & 0xED; /* reset ACK bit and SYN bit */
            SYN_send_bit = (SYN_send) ? 0x02 : 0x00; /* Decide whether SYN bit is on */
            ACK_send_bit = (ACK_send) ? 0x10 : 0x00; /* Decide whether ACK bit is on */
            /* TODO FIN_send_bit setting and add it to all_flags_send */
            flags_send_temp = ( flags_send_temp | SYN_send_bit ) | ACK_send_bit;
            all_flags_send[0] = flags_send_temp;

            /* Set SEQ_num_send and ACK_num_send */
            SEQ_num_send[0] = htonl(socket_target->SEQ_num);
            printf("==== 1 SEQ_num to send = %d ====\n", socket_target->SEQ_num);
            (socket_target->SEQ_num)++;
            printf("==== 2 SEQ_num to send = %d ====\n", socket_target->SEQ_num);
            if ( ACK_recv ){
                printf("==== 1 ACK_num to send = %d ====\n", SEQ_num_recv_h);
                ACK_num_send[0] = htonl(SEQ_num_recv_h + (uint32_t) 1);
                printf("==== 2 ACK_num to send = %d ====\n", SEQ_num_recv_h + (uint32_t) 1);
            }
            else
                ACK_num_send[0] = htonl((uint32_t) 0);

            /* Create a Packet */
            createPacketHeader(packet_send, dest_ip, src_ip, dest_port, src_port,
                               SEQ_num_send, ACK_num_send, all_flags_send);

            /* Send the Packet */
            this->sendPacket("IPv4", packet_send);
        }

        /* Change the current state of socket */
        state_machine_socket->transit(recv_signal);
        /* If the socket is in state ESTABLISHED, call returnSystemCall */
        StateNode* target_node = state_machine_socket->GetCurrentState();
        /* TODO: Set the ret value */
        if ( target_node->GetLabel() == Label::ESTABLISHED ){
            int ret;
            int socket_type = state_machine_socket->GetMachineType();
            if ( socket_type == (int) MachineType::CLIENT)
                ret = 0;
            else {/* socket_target_MachineType == MachineType::SERVER */
                /* TODO case for accept */
                int target_port_fd = 10; /* TODO Have to change this part */
                ret = target_port_fd;
            }
            UUID* UUID_ptr = (UUID*) (socket_target->syscallUUID);
            returnSystemCall(*UUID_ptr, ret );
        }

        socket_b.delete_socket(file_target.fd);
        socket_b.put_socket(file_target.fd, *socket_target);

        this->freePacket(packet);
        int ret = 0;
        UUID* UUID_ptr = (UUID*) (socket_target->syscallUUID);

        returnSystemCall(*UUID_ptr, ret );
        printf(" ============================= \n");
    }

    void TCPAssignment::createPacketHeader(Packet* packet_send, uint32_t* src_ip, uint32_t* dest_ip,
            uint16_t* src_port, uint16_t* dest_port, uint32_t* SEQ_num, uint32_t* ACK_num, uint8_t* all_flags){
        /* Set Packet */
        /* Src/Dest Ip addr and port number */
        uint16_t checksum_ = (uint16_t) 0;
        packet_send->writeData(14+12, src_ip, 4);
        packet_send->writeData(14+16, dest_ip, 4);
        packet_send->writeData(14+20+0, src_port, 2);
        packet_send->writeData(14+20+2, dest_port, 2);

        /* ACK num and SEQ num */
        packet_send->writeData(14+20+4, SEQ_num, 4);
        packet_send->writeData(14+20+8, ACK_num, 4);

        packet_send->writeData(14+20+13, all_flags, 1);
//        packet_send->writeData(14+20+16, &(checksum_), 2);

        /* Calculating Checksum */
        checksum_ = checksum((unsigned short*) packet_send, 54);

        packet_send->writeData(14+20+16, &(checksum_), 2);

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

//Util function

    StateNode::StateNode(Label label, char *str_label): label(label) {
        strcpy(this->str_label, str_label);
    }

    StateNode::StateNode(): label(Label::NONE){}

    StateLink::StateLink(StateNode *state_node, StateNode *next_node,
                         Signal recv, Signal send) {
        this->state_node = state_node;
        this->next_node = next_node;
        this->recv = recv;
        this->send = send;

        // String for debug.
        char str1[80];
        char str2[80];
        strcpy(str1, state_node->ToString());
        strcpy(str2, next_node->ToString());
        strcat(str1, "-->");
        strcat(str1, str2);
        strcpy(this->str_link, str1);
    }

    StateMachine::StateMachine(MachineType machine_type) {
        //    GenerateStateTable();
        this->current_state_ptr = E::state_label_table[0];

        this->machine_type = machine_type;

        if (machine_type == MachineType::CLIENT) {
            // CLIENT state machine
            this->state_link_table = E::cli_closed_table;
        } else {
            // SERVER state machine
            this->state_link_table = E::serv_closed_table;
        }
    }

    StateMachine::~StateMachine() {
        free(this->current_state_ptr);
        free(this->state_link_table);
    }

    Signal StateMachine::getSendSignal(Signal recv) {
        StateNode *currentNode = GetCurrentState();
        Label currentLabel = currentNode->GetLabel();

        for (int i = 0; i < 3; i++) {
            StateLink *state_link_ptr = state_link_table[i];
            if (state_link_ptr->GetRecv() == recv) {
                return state_link_ptr->GetSend();
            }
        }
        return Signal::ERR;
    }

    char *PrintSignal(Signal signal) {
        switch (signal) {
            case Signal::SYN:
                return "SYN";
            case Signal::ACK:
                return "ACK";
            case Signal::FIN:
                return "FIN";
            case Signal::SYN_ACK:
                return "SYN ACK";
            case Signal::FIN_ACK:
                return "FIN ACK";
            case Signal::OPEN:
                return "OPEN";
            case Signal::CLOSE:
                return "CLOSE";
            case Signal::DATA:
                return "DATA";
            case Signal::ERR:
                return "ERROR";
            case Signal::NONE:
                return "NONE";
            default:
                return "ERROR!!";
        }
    }

    int getIndexFromLabel(Label *label_table, Label label, int table_size) {
        for (int i = 0; i < table_size; i++) {
            if (label_table[i] == label) {
                return i;
            }
        }
        return -1;
    };

    int StateMachine::transit(Signal recv) {
        int index;
        StateNode *next_node = getNextNode(recv);
        if (next_node == nullptr) {
            return -1;
        }

        current_state_ptr = next_node;

        Label newLabel = current_state_ptr->GetLabel();

        if (this->machine_type == MachineType::CLIENT) {
            index = getIndexFromLabel(cli_label_table, newLabel, 7);
            this->state_link_table = cli_link_table[index];
        } else {
            index = getIndexFromLabel(serv_label_table, newLabel, 6);
            this->state_link_table = serv_link_table[index];
        }

        return 1;
    }

    StateNode* StateMachine::getNextNode(Signal recv) {
        StateNode *currentNode = GetCurrentState();

        Label currentLabel = currentNode->GetLabel();

        for (int i = 0; i < 3; i++) {
            StateLink *state_link_ptr = this->state_link_table[i];
            if (state_link_ptr->GetRecv() == recv) {
                printf("%s: \n", state_link_ptr->ToString());
                return state_link_ptr->GetNextNode();
            }
        }
        return nullptr; // node_err
    }

    void StateMachine::log() {
        char *current_state = this->current_state_ptr->ToString();
        printf("%s\n", current_state);
    }
}
