/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

namespace E {
    enum class MachineType {
        SERVER, CLIENT, SERVER_CLIENT
    };

    enum class Label {
        CLOSED, LISTEN, SYN_RCVD,
        SYN_SENT, ESTABLISHED, CLOSE_WAIT,
        LAST_ACK, FIN_WAIT_1, CLOSING,
        FIN_WAIT_2, TIME_WAIT, NONE
    };

    enum class Signal {
        SYN, ACK, FIN, SYN_ACK, FIN_ACK, OPEN, CLOSE, DATA, ERR, NONE
    }; // err contains timeout

    struct Connection {
        uint32_t seq_num;
        uint32_t ack_num;
        int established = 0;
        sockaddr_in *cli_addr_ptr;
        int peer_fd;
        int fd;
    };

    struct ConnectionBucket {
        int not_established = 0;
        std::vector<Connection *> connections;
    };

    struct pseudoHeader {
        uint32_t src_ip;
        uint32_t dest_ip;
        uint8_t reserved;
        uint8_t protocol;
        uint16_t TCP_segment_length;
    };

    struct Socket {
        int fd;
        int pid;
        int max_backlog;
        ConnectionBucket *backlog = new ConnectionBucket;
        std::vector<int> cli_sockets = std::vector<int>();
        Label state_label;
        MachineType socket_type;

        int domain;
        int type;
        int protocol;
        int is_bind = 0;
        int is_timewait;

        struct sockaddr *addr_ptr;
        socklen_t sock_len;

        uint32_t seq_num;
        uint32_t ack_num;

        UUID syscallUUID;
    };


    struct SocketBucket {
        std::vector<Socket *> sockets;
    };

    struct TCPHeader {
        uint16_t src_port;
        uint16_t dest_port;

        uint32_t seq_num;
        uint32_t ack_num;

        uint8_t head_length;
        uint8_t offset_res_flags;
        uint16_t window;
        uint16_t checksum;
        uint16_t urgent_ptr;
    };

    class Debug {
    public:
        Debug(){};

        void Log(char *string) {
            printf("========== %s ==========\n", string);
        };

        void Log(char *string, char *string2) {
            printf("========== %s %s ==========\n", string, string2);
        };

        void Log(char *string, int num) {
            printf("========== %s: %d ==========\n", string, num);
        };

        void Log(char *string, uint8_t num) {
            printf("========== %s: %d ==========\n", string, num);
        };

        void LogDivider() {
            printf("*******************************\n");
        };

        void Log(Label label) {
            ToString(label, this->debug_str);
            printf("Label: %s\n", debug_str);
        };

        void Log(Signal signal) {
            ToString(signal, this->debug_str);
            printf("Label: %s\n", debug_str);
        };

        void Log(Connection connection) {
            ToString(connection, this->debug_str);
            printf("Label: %s\n", debug_str);
        };

        void Log(MachineType machine_type) {
            ToString(machine_type, this->debug_str);
            printf("Label: %s\n", debug_str);
        };
    private:
        char debug_str[50];

        void ToString(Label label, char *ret_string);

        void ToString(Signal signal, char *ret_string);

        void ToString(Connection connection, char *ret_string);

        void ToString(MachineType machineType, char *ret_string);
    };

    struct BlockValue {
        struct sockaddr *sockaddr_ptr;
        socklen_t *socklen_ptr;
        int pid;
        int fd;
    };

    class TCPAssignment
            : public HostModule,
              public NetworkModule,
              public SystemCallInterface,
              private NetworkLog,
              private TimerModule {

    private:
        virtual void timerCallback(void *payload) final;

        void CreatePacketHeader(
                Packet *packet, TCPHeader *packet_header, uint32_t *src_ip, uint32_t *dest_ip, int length);

        void CreatePacketHeaderWithFlag(
                uint8_t *flags,
                Socket *socket_ptr,
                Packet *packet,
                TCPHeader *packet_header,
                uint32_t *src_ip,
                uint32_t *dest_ip,
                int length);

    public:
        SocketBucket socket_bucket;
        SocketBucket cli_bucket;

        char debug_str[50];

        Debug *debug = new Debug();

        TCPAssignment(Host *host);

        void syscall_socket(
                UUID syscallUUID, int pid, int param1_int, int param2_int);
        void syscall_close(
                UUID syscallUUID,  int pid, int fd);

        void syscall_getsockname(
                UUID syscallUUID,
                int pid,
                int param1,
                struct sockaddr *param2_ptr, socklen_t *param3_ptr);

        void syscall_bind(
                UUID syscallUUId,
                int pid, int fd, struct sockaddr *sockaddr_ptr, socklen_t socklen_ptr);

        void syscall_connect(UUID syscallUUID, int pid, int client_fd,
                             struct sockaddr* server_addr, socklen_t server_addr_length);

        void syscall_listen(UUID syscallUUID, int pid, int server_fd, int max_backlog);

        void syscall_accept(UUID syscallUUID, int pid, int listen_fd,
                            struct sockaddr* client_addr, socklen_t* client_addr_len);

        void syscall_getpeername(UUID syscallUUID, int pid, int listen_fd,
                                 struct sockaddr* client_addr, socklen_t *client_addr_len);

        unsigned short checksum(unsigned short* ptr_packet, int size_packet);

        virtual void initialize();

        virtual void finalize();

        virtual ~TCPAssignment();

    protected:
        virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter &param) final;

        virtual void packetArrived(std::string fromModule, Packet *packet) final;
    };

    class TCPAssignmentProvider {
    private:
        TCPAssignmentProvider() {}

        ~TCPAssignmentProvider() {}

    public:
        static HostModule *allocate(Host *host) { return new TCPAssignment(host); }
    };

    class StateMachine {
    public:
        StateMachine() : current_node(Label::CLOSED), machine_type(MachineType::CLIENT) {};

        StateMachine(Label label, MachineType machineType) : current_node(label), machine_type(machineType) {};

        Label GetCurrentState() { return current_node; };

        MachineType GetSocketType() { return machine_type; };

        int Transit(Signal recv);

        Signal GetSendSignalAndSetNextNode(Signal recv);

    private:
        Label current_node;
        Label next_node;
        MachineType machine_type;
    };


}

namespace state_machine {

}

#endif /* E_TCPASSIGNMENT_HPP_ */