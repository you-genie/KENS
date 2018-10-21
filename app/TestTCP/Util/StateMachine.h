//
// Created by 정유진 on 2018. 10. 21..
//

#ifndef KENSV3_STATEMACHINE_H
#define KENSV3_STATEMACHINE_H

#endif //KENSV3_STATEMACHINE_H

namespace state_machine
{
    enum class Label { CLOSED, LISTEN, SYN_RCVD,
            SYN_SENT, ESTABLISHED, CLOSE_WAIT,
            LAST_ACK, FIN_WAIT_1, CLOSING,
            FIN_WAIT_2, TIME_WAIT };

    enum class Signal { SYN, ACK, FIN, SYN_ACK, OPEN, CLOSE, DATA, ERR }; // err contains timeout

    /*
     * Interface for each state node.
     */
    class StateInterface {
    public:
        virtual Signal GetTransitSignal(Signal recv);
        virtual ~StateInterface();
    private:
        virtual bool isValid(Signal recv); // recv: Signal that received. Application also.
    };

    class StateNode: StateInterface {
    public:
        Label state_label;
        StateNode nextState;
        Signal transit_signal; // Signal that StateNode should send.
    };
}