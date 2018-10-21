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
    class StateNode {
    public:
        Label state_label;
        StateNode nextNode;
        virtual Signal GetTransit(Signal recv);
    private:
        virtual bool isValid(Signal recv);
    };
}