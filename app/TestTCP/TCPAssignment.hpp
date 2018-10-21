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

}


#endif /* E_TCPASSIGNMENT_HPP_ */
