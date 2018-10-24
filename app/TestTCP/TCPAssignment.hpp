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

    class TCPAssignment
            : public HostModule,
              public NetworkModule,
              public SystemCallInterface,
              private NetworkLog,
              private TimerModule {
    private:

    private:
        virtual void timerCallback(void *payload) final;

    public:
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

        void createPacketHeader(Packet* packet_send, uint32_t* src_ip, uint32_t* dest_ip,
                                uint16_t* src_port, uint16_t* dest_port, uint32_t* SEQ_num, uint32_t* ACK_num, uint8_t* all_flags);

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

    enum class MachineType {
        SERVER, CLIENT
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

    class StateNode {
    public:
        StateNode();

        StateNode(Label label, char *str_label);

        char *ToString() { return str_label; };

        Label GetLabel() { return label; };
    private:
        Label label;
        char str_label[20];
    };

    class StateLink {
    public:
        StateLink(StateNode *state_node, StateNode *next_node, Signal recv, Signal send);

        Signal GetRecv() { return recv; };

        Signal GetSend() { return send; };

        StateNode *GetNextNode() { return next_node; };

        // TODO: generate str_link on this function
        char *ToString() { return str_link; };
    private:
        StateNode *state_node = new StateNode();
        StateNode *next_node;
        char str_link[80];
        Signal recv;
        Signal send;
    };

    struct LabelMap {
        Label label;
        StateLink *link_map[3];
    };

    class StateMachine {
    public:
        StateMachine(MachineType machine_type);

        StateMachine(MachineType machine_type, Label label);

        ~StateMachine();

        int GetMachineType() { return (int) machine_type; };

        StateNode *GetCurrentState() { return current_state_ptr; };

        Signal GetSendSignal(Signal recv) { return getSendSignal(recv); };

        int transit(Signal recv); // TODO: return -1 if not valid signal.
        void log(); // TODO: log all the actions, receiving link and stateNode value.
    private:
        StateNode *current_state_ptr;
        StateLink **state_link_table;
        MachineType machine_type;

        StateNode *getNextNode(Signal recv);

        Signal getSendSignal(Signal recv); // TODO: give Signal::ERR if is not valid.
    };

}

namespace state_machine {

}

#endif /* E_TCPASSIGNMENT_HPP_ */
