/*
//
// Created by 정유진 on 2018. 10. 21..
//

#ifndef KENSV3_STATEMACHINE_H
#define KENSV3_STATEMACHINE_H

#endif //KENSV3_STATEMACHINE_H

namespace state_machine {
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

    Label cli_label_table[7] = {
            Label::CLOSED, Label::SYN_SENT, Label::ESTABLISHED,
            Label::FIN_WAIT_1, Label::FIN_WAIT_2, Label::CLOSING,
            Label::TIME_WAIT
    };

    Label serv_label_table[6] = {
            Label::CLOSED, Label::LISTEN, Label::SYN_RCVD,
            Label::ESTABLISHED, Label::CLOSE_WAIT, Label::LAST_ACK
    };

    void GenerateStateTable();

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
    StateLink *link_closed_to_listen = new StateLink(node_closed, node_listen, Signal::NONE, Signal::NONE);
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

    int getIndexFromLabel(Label *label_table, Label label, int table_size) {
        for (int i = 0; i < table_size; i++) {
            if (label_table[i] == label) {
                return i;
            }
        }
        return -1;
    };

    class StateMachine {
    public:
        StateMachine(MachineType machine_type);

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
}*/
