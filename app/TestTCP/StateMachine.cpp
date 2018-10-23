////
//// Created by 정유진 on 2018. 10. 22..
////
//#include "StateMachine.h"
//#include <stdio.h>
//#include <string.h>
//
//using state_machine::Label;
//using state_machine::Signal;
//using state_machine::MachineType;
//using state_machine::StateMachine;
//using state_machine::LabelMap;
//using state_machine::StateLink;
//using state_machine::StateNode;
//using state_machine::state_label_table;
//using namespace state_machine;
//
//StateNode::StateNode(state_machine::Label label, char *str_label): label(label) {
//    strcpy(this->str_label, str_label);
//}
//
//StateNode::StateNode(): label(Label::NONE){}
//
//StateLink::StateLink(StateNode *state_node, StateNode *next_node,
//        Signal recv, Signal send) {
//    this->state_node = state_node;
//    this->next_node = next_node;
//    this->recv = recv;
//    this->send = send;
//
//    // String for debug.
//    char str1[80];
//    char str2[80];
//    strcpy(str1, state_node->ToString());
//    strcpy(str2, next_node->ToString());
//    strcat(str1, "-->");
//    strcat(str1, str2);
//    strcpy(this->str_link, str1);
//}
//
////void state_machine::GenerateStateTable() {
////    //Generate state_node map.
////    StateNode *node_closed = new StateNode(Label::CLOSED, "Closed");
////    StateNode *node_syn_sent = new StateNode(Label::SYN_SENT, "Syn Sent");
////    StateNode *node_established = new StateNode(Label::ESTABLISHED, "Established");
////    StateNode *node_fin_wait_1 = new StateNode(Label::FIN_WAIT_1, "Fin Wait 1");
////    StateNode *node_fin_wait_2 = new StateNode(Label::FIN_WAIT_2, "Fin Wait 2");
////    StateNode *node_closing = new StateNode(Label::CLOSING, "Closing");
////    StateNode *node_time_wait = new StateNode(Label::TIME_WAIT, "Time Wait");
////    StateNode *node_listen = new StateNode(Label::LISTEN, "Listen");
////    StateNode *node_syn_rcvd = new StateNode(Label::SYN_RCVD, "Syn Received");
////    StateNode *node_close_wait = new StateNode(Label::CLOSE_WAIT, "Close Wait");
////    StateNode *node_last_ack = new StateNode(Label::LAST_ACK, "Last Ack");
////    StateNode *node_none = new StateNode(Label::NONE, "None");
////
////    StateNode *new_state_label_table[12] = {
////            node_closed, node_listen, node_syn_rcvd,
////            node_syn_sent, node_established, node_close_wait,
////            node_last_ack, node_fin_wait_1, node_closing,
////            node_fin_wait_2, node_time_wait, node_none
////    };
////
////    state_label_table = new_state_label_table;
////
////    StateLink *link_none = new StateLink(node_none, node_none, Signal::NONE, Signal::NONE);
////
////    // For client
////    StateLink *link_closed_to_syn_sent = new StateLink(node_closed, node_syn_sent, Signal::OPEN, Signal::SYN);
////    StateLink *new_cli_closed_table[3] = {
////            link_closed_to_syn_sent, link_none, link_none };
////    cli_closed_table = new_cli_closed_table;
////
////    StateLink *link_syn_sent_to_established =
////            new StateLink(node_syn_sent, node_established, Signal::SYN_ACK, Signal::ACK);
////    StateLink *link_syn_sent_to_closed = new StateLink(node_syn_sent, node_closed, Signal::ERR, Signal::NONE);
////    StateLink *new_cli_syn_sent_table[3] = {
////            link_syn_sent_to_established,
////            link_syn_sent_to_closed,
////            link_none
////    };
////    cli_syn_sent_table = new_cli_closed_table;
////
////    StateLink *link_established_to_fin_wait_1 =
////            new StateLink(node_established, node_fin_wait_1, Signal::CLOSE, Signal::FIN);
////    StateLink *new_cli_established_table[3] = {
////            link_established_to_fin_wait_1, link_none, link_none};
////    cli_established_table = new_cli_established_table;
////
////    StateLink *link_fin_wait_1_to_closing = new StateLink(node_fin_wait_1, node_closing, Signal::FIN, Signal::ACK);
////    StateLink *link_fin_wait_1_to_time_wait =
////            new StateLink(node_fin_wait_1, node_time_wait, Signal::FIN_ACK, Signal::ACK);
////    StateLink *link_fin_wait_1_to_fin_wait_2 =
////            new StateLink(node_fin_wait_1, node_fin_wait_2, Signal::ACK, Signal::NONE);
////    StateLink *new_cli_fin_wait_1_table[3] = {
////            link_fin_wait_1_to_closing,
////            link_fin_wait_1_to_fin_wait_2,
////            link_fin_wait_1_to_time_wait
////    };
////    cli_fin_wait_1_table = new_cli_fin_wait_1_table;
////
////    StateLink *link_closing_to_time_wait = new StateLink(node_closing, node_time_wait, Signal::ACK, Signal::NONE);
////    StateLink *new_cli_closing_table[3] = {
////            link_closing_to_time_wait, link_none, link_none
////    };
////    cli_closing_table = new_cli_closing_table;
////
////    StateLink *link_fin_wait_2_to_time_wait = new StateLink(node_fin_wait_2, node_time_wait, Signal::FIN, Signal::ACK);
////    StateLink *cli_fin_wait_2_table[3] = {
////            link_fin_wait_2_to_time_wait, link_none, link_none};
////
////    StateLink *link_time_wait_to_closed = new StateLink(node_time_wait, node_closed, Signal::ERR, Signal::NONE);
////    StateLink *new_cli_time_wait_table[3] = {
////            link_time_wait_to_closed, link_none, link_none};
////    cli_time_wait_table = new_cli_time_wait_table;
////
////    // For server
////    StateLink *link_closed_to_listen = new StateLink(node_closed, node_listen, Signal::NONE, Signal::NONE);
////    StateLink *serv_closed_table[3] = {
////            link_closed_to_listen, link_none, link_none};
////
////    StateLink *link_listen_to_syn_rcvd = new StateLink(node_listen, node_syn_rcvd, Signal::SYN, Signal::SYN_ACK);
////    StateLink *serv_listen_table[3] = {
////            link_listen_to_syn_rcvd, link_none, link_none};
////
////    StateLink *link_syn_rcvd_to_closed = new StateLink(node_syn_rcvd, node_closed, Signal::ERR, Signal::NONE);
////    StateLink *link_syn_rcvd_to_established = new StateLink(node_syn_rcvd, node_established, Signal::ACK, Signal::NONE);
////    StateLink *serv_syn_rcvd_table[3] = {
////            link_syn_rcvd_to_closed,
////            link_syn_rcvd_to_established,
////            link_none
////    };
////
////    StateLink *link_established_to_close_wait =
////            new StateLink(node_established, node_close_wait, Signal::FIN, Signal::ACK);
////    StateLink *serv_established_table[3] = {
////            link_established_to_close_wait, link_none, link_none};
////
////    StateLink *link_close_wait_to_last_ack = new StateLink(node_close_wait, node_last_ack, Signal::CLOSE, Signal::ACK);
////    StateLink *serv_close_wait_table[3] = {
////            link_close_wait_to_last_ack, link_none, link_none};
////
////    StateLink *link_last_ack_to_closed = new StateLink(node_last_ack, node_closed, Signal::ACK, Signal::NONE);
////    StateLink *serv_last_ack_table[3] = {
////            link_last_ack_to_closed, link_none, link_none};
////
////    StateLink **cli_link_table[7] = {
////            cli_closed_table, cli_syn_sent_table, cli_established_table,
////            cli_fin_wait_1_table, cli_fin_wait_2_table, cli_closing_table,
////            cli_time_wait_table
////    };
////
////    StateLink **serv_link_table[6] = {
////            serv_closed_table, serv_listen_table, serv_syn_rcvd_table,
////            serv_established_table, serv_close_wait_table, serv_last_ack_table
////    };
////
////}
//
//StateMachine::StateMachine(state_machine::MachineType machine_type) {
////    GenerateStateTable();
//    this->current_state_ptr = state_label_table[0];
//
//    this->machine_type = machine_type;
//
//    if (machine_type == MachineType::CLIENT) {
//        // CLIENT state machine
//        this->state_link_table = cli_closed_table;
//    } else {
//        // SERVER state machine
//        printf("ABD\n");
//        this->state_link_table = serv_closed_table;
//    }
//}
//
//Signal StateMachine::getSendSignal(state_machine::Signal recv) {
//    StateNode *currentNode = GetCurrentState();
//    Label currentLabel = currentNode->GetLabel();
//
//    for (int i = 0; i < 3; i++) {
//        StateLink *state_link_ptr = state_link_table[i];
//        if (state_link_ptr->GetRecv() == recv) {
//            return state_link_ptr->GetSend();
//        }
//    }
//    return Signal::ERR;
//}
//
//StateNode* StateMachine::getNextNode(Signal recv) {
//    StateNode *currentNode = GetCurrentState();
//
//    Label currentLabel = currentNode->GetLabel();
//
//    for (int i = 0; i < 3; i++) {
//        StateLink *state_link_ptr = this->state_link_table[i];
//        if (state_link_ptr->GetRecv() == recv) {
//            printf("%s: \n", state_link_ptr->ToString());
//            return state_link_ptr->GetNextNode();
//        }
//    }
//    return nullptr; // node_err
//}
//
//void StateMachine::log() {
//    char *current_state = this->current_state_ptr->ToString();
//    printf("%s\n", current_state);
//}
//
//int StateMachine::transit(state_machine::Signal recv) {
//    int index;
//    StateNode *next_node = getNextNode(recv);
//    if (next_node == nullptr) {
//        return -1;
//    }
//
//    current_state_ptr = next_node;
//
//    Label newLabel = current_state_ptr->GetLabel();
//
//    if (this->machine_type == MachineType::CLIENT) {
//        index = getIndexFromLabel(cli_label_table, newLabel, 7);
//        this->state_link_table = cli_link_table[index];
//    } else {
//        index = getIndexFromLabel(serv_label_table, newLabel, 6);
//        this->state_link_table = serv_link_table[index];
//    }
//
//    return 1;
//}
//
//
////int main() {
////    StateMachine *stateMachine = new StateMachine(MachineType::SERVER);
////
////    char key[80];
////    while (1) {
////        printf("\nPress key, current state is: ");
////        stateMachine->log();
////        printf("\n");
////        scanf("%s", key);
////
////        Signal signal = Signal::NONE;
////        if (strncmp(key,"q",80) == 0) {
////            return -1;
////        }
////        else if (strncmp(key, "ack", 80) == 0) {
////            signal = Signal::ACK;
////        }
////        else if (strncmp(key, "syn", 80) == 0) {
////            signal = Signal::SYN;
////        }
////        else if (strncmp(key, "open", 80) == 0) {
////            signal = Signal::OPEN;
////        }
////        else if (strncmp(key, "close", 80) == 0) {
////            signal = Signal::CLOSE;
////        }
////        else if (strncmp(key, "syn_ack", 80) == 0) {
////            signal = Signal::SYN_ACK;
////        }
////        else if (strncmp(key, "fin", 80) == 0) {
////            signal = Signal::FIN;
////        }
////        else if (strncmp(key, "fin_ack", 80) == 0) {
////            signal = Signal::SYN_ACK;
////        }
////        else if (strncmp(key, "data", 80) == 0) {
////            signal = Signal::DATA;
////        }
////        else if (strncmp(key, "err", 80) == 0) {
////            signal = Signal::ERR;
////        }
////        else if (strncmp(key, "none", 80) == 0) {
////            signal = Signal::NONE;
////        }
////        else {
////            printf("ERROR!!!!!");
////            return -1;
////        }
////
////        Signal send_signal = stateMachine->GetSendSignal(signal);
////        char *signal_str = state_machine::PrintSignal(send_signal);
////
////        printf("Send: %s\n", signal_str);
////
////        if (stateMachine->transit(signal) == -1) {
////            printf("ERROOooOOOR: \n");
////        } else {
////        }
////    }
////    return 1;
////}