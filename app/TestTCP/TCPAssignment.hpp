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
    enum Error {
        ERR_BASIC = -1,
        ERR_DATA_SIZE_OVERFLOW = -2,
        ERR_RCWD_OVERFLOW = -3
    };

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
    };

    struct DataHolder {
        char *data = new char;
        int data_size;
        int seq_num;
    };

    struct WriteBuffer {
        int rwnd;
        int max_size = 4096;
        int unack_size = 4096;
        std::vector<DataHolder *> packet_data_bucket = std::vector<DataHolder *>();
    };

    struct ReadBuffer {
        int rwnd;
        int max_size = 4096;
        int last_rcvd_size;
        int last_read_size;
        std::vector<DataHolder *> packet_data_bucket = std::vector<DataHolder *>();
    };

    struct Connection {
        uint32_t seq_num;
        uint32_t ack_num;
        int established = 0;
        sockaddr_in *cli_addr_ptr;
        int peer_fd;
        int fd;
    };

    struct Peer {
        sockaddr_in *peer_addr_ptr;
        int peer_fd;
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
        std::vector<int> backlog_ready = std::vector<int>();
        Label state_label;
        MachineType socket_type;

        int domain;
        int type;
        int protocol;
        int is_bind = 0;
        int is_timewait;
        int send_fin = 0;
        int close_fin = 0;
        int close_ack = 0;

        struct sockaddr *addr_ptr;
        socklen_t sock_len;

        uint32_t seq_num;
        uint32_t ack_num;

        Peer *peer_values = new Peer;

        WriteBuffer *writeBuffer = new WriteBuffer;
        ReadBuffer *readBuffer = new ReadBuffer;
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
        Debug() {};

        void Log(char *string) {
            printf("%s\n", string);
        };

        void BigLog(char *string) {
            printf("========== %s ==========\n", string);
        }

        void StarLog(char *string) {
            printf("** %s **\n", string);
        }

        void StarLog(char *string, int num) {
            printf("** %s: %d **\n", string, num);
        }

        void StarLog(char *string, uint8_t num) {
            printf("** %s: %d **\n", string, num);
        };

        void Log(char *string, char *string2) {
            printf("%s: %s\n", string, string2);
        };

        void Log(char *string, int num) {
            printf("%s: %d\n", string, num);
        };

        void Log(char *string, uint8_t num) {
            printf("%s: %d\n", string, num);
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
            printf("Signal: %s\n", debug_str);
        };

        void Log(Connection connection) {
            ToString(connection, this->debug_str);
            printf("Connection: %s\n", debug_str);
        };

        void Log(MachineType machine_type) {
            ToString(machine_type, this->debug_str);
            printf("Socket Type: %s\n", debug_str);
        };

        void Log(Error error) {
            ToString(error, this->debug_str);
            printf("Error Message: %s\n", debug_str);
        }

    private:
        char debug_str[50];

        void ToString(Label label, char *ret_string);

        void ToString(Signal signal, char *ret_string);

        void ToString(Connection connection, char *ret_string);

        void ToString(MachineType machineType, char *ret_string);

        void ToString(Error error, char *ret_string) {
            switch (error) {
                case ERR_BASIC:
                    memcpy(ret_string, "basic error", sizeof(50));
                    break;
                case ERR_DATA_SIZE_OVERFLOW:
                    memcpy(ret_string, "data size is over buffer size", sizeof(50));
                    break;
                case ERR_RCWD_OVERFLOW:
                    memcpy(ret_string, "data size is over rcwd", sizeof(50));
            }
        }
    };

    struct BlockValue {
        struct sockaddr *sockaddr_ptr;
        socklen_t *socklen_ptr;
        int pid;
        int fd;
        int isCalled = 0;
        UUID syscallUUID;
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

        /**
         *
         * @param seq_num
         * @param index 여기다가 인덱스 담아주기
         * @param write_buffer
         * @return index value, if no such data exist, -1
         * 여기서 -1이 난다는 거는요 중간에 ack=100 ack=100 ack=100같은거
         */
        int FindDataIndexWithSeq(int seq_num, WriteBuffer *write_buffer);

        /**
         * 다 지우는 로직 좀 짜봅시다 내가 까먹음
         * @param index 얘로 지움. a.erase(...begin() + index);
         * @param write_buffer
         * @return -1 에러라면!
         * 아닌 경우 지우는 데이터 사이즈를 리턴한다.
         */
        int DeleteDataWithIndex(int index, WriteBuffer *write_buffer);

    public:
        BlockValue *block_value = new BlockValue;
        BlockValue *listen_value = new BlockValue;

        SocketBucket socket_bucket;
        SocketBucket cli_bucket;

        char debug_str[50];

        Debug *debug = new Debug();

        TCPAssignment(Host *host);

        /**
         * seq_num으로 찾아서 (FindDataIndexWithSeq) DeleteDataWithIndex로 지움.
         * @param seq_num
         * @param write_buffer
         * @return -1 에러라면!!!
         */
        int DeleteDataWithSeq(int seq_num, WriteBuffer *write_buffer);

        /**
         * safe coding 필요함. 맥스 사이즈에서 알아서 뺴서 섹폴 안나게
         * 읽은 만큼 없애야됨!!!!!!!!!!!!!
         *  *** 여기서 len이 더 긴 경우 다 읽으면 됨.
         * @param data_ret 여기다가
         * @param len 요만큼
         * @param read_buffer 여기서 읽어서 복사하세요. 아마 memcpy로 하는 게 복장터지지않을듯
         * @return -1 에러면
         */
        int ReadDataWithLen(char *data_ret, int len, ReadBuffer *read_buffer);

        /**
         * 저거 위에 있는 DeleteDataWithIndex처럼 똑같이하면될걸?
         * @param index 이만큼
         * @param read_buffer 여기에서 지워주세요.
         * @return
         */
        int DeleteDataWithLen(int index, ReadBuffer *read_buffer);

        void syscall_socket(
                UUID syscallUUID, int pid, int param1_int, int param2_int);

        void syscall_close(
                UUID syscallUUID, int pid, int fd);

        void syscall_getsockname(
                UUID syscallUUID,
                int pid,
                int param1,
                struct sockaddr *param2_ptr, socklen_t *param3_ptr);

        void syscall_bind(
                UUID syscallUUId,
                int pid, int fd, struct sockaddr *sockaddr_ptr, socklen_t socklen_ptr);

        void syscall_connect(UUID syscallUUID, int pid, int client_fd,
                             struct sockaddr *server_addr, socklen_t server_addr_length);

        void syscall_listen(UUID syscallUUID, int pid, int server_fd, int max_backlog);

        void syscall_accept(UUID syscallUUID, int pid, int listen_fd,
                            struct sockaddr *client_addr, socklen_t *client_addr_len);

        void syscall_getpeername(UUID syscallUUID, int pid, int listen_fd,
                                 struct sockaddr *client_addr, socklen_t *client_addr_len);

        void syscall_read(UUID syscallUUID, int pid, int fd, void *read_content, int size_read);

        void syscall_write(UUID syscallUUID, int pid, int fd, void *write_content, int size_write);


        unsigned short checksum(unsigned short *ptr_packet, int size_packet);

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