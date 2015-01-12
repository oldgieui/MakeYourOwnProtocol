//
// fsm.c
// FSM sample code
//
// Created by Minsuk Lee, 2014.11.1.
// Copyright (c) 2014. Minsuk Lee All rights reserved.
// see LICENSE

#include "util.h"

#define CONNECT_TIMEOUT 5

#define NUM_STATE   4
#define NUM_EVENT   8

enum pakcet_type { F_CON = 0, F_FIN = 1, F_ACK = 2, F_DATA = 3 };   // Packet Type
enum proto_state { wait_CON = 0, CON_sent = 1, CONNECTED = 2, RETRANSMISSION};     // States

// Events
enum proto_event { RCV_CON = 0, RCV_FIN = 1, RCV_ACK = 2, RCV_DATA = 3,
                   CONNECT = 4, CLOSE = 5,   SEND = 6,    TIMEOUT = 7 };

char *pkt_name[] = { "F_CON", "F_FIN", "F_ACK", "F_DATA" };
char *st_name[] =  { "wait_CON", "CON_sent", "CONNECTED", "RETRANSMISSION" };
char *ev_name[] =  { "RCV_CON", "RCV_FIN", "RCV_ACK", "RCV_DATA",
                     "CONNECT", "CLOSE",   "SEND",    "TIMEOUT"   };

struct state_action {           // Protocol FSM Structure
    void (* action)(void *p);
    enum proto_state next_state;
};

unsigned int data_count = 0;
int packet_index = 0;

#define MAX_DATA_SIZE   (500)
struct packet {                 // 504 Byte Packet to & from Simulator
    unsigned short type;        // enum packet_type
    unsigned short size;
    int index;
    char data[MAX_DATA_SIZE];
};

struct p_event {                // Event Structure
    enum proto_event event;
    struct packet packet;
    struct packet recv_packet;
    int size;
};

struct packet stored_packet;

enum proto_state c_state = wait_CON;         // Initial State
volatile int timedout = 0;

static void timer_handler(int signum)
{
    printf("Timedout\n");
    timedout = 1;
}

static void timer_init(void)
{
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = &timer_handler;
    sigaction(SIGALRM, &sa, NULL);
}

void set_timer(int sec)
{
    struct itimerval timer;

    timedout = 0;
    timer.it_value.tv_sec = sec;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;   // Non Periodic timer
    timer.it_interval.tv_usec = 0;
    setitimer (ITIMER_REAL, &timer, NULL);
}
void send_packet(int flag, void *p, int size, int index)
{
    struct packet pkt;
    printf("SEND %s\n", pkt_name[flag]);

    pkt.type = flag;
    pkt.size = size;
    pkt.index = index;

    if (size)
        memcpy(pkt.data, ((struct p_event *)p)->packet.data, (size > MAX_DATA_SIZE) ? MAX_DATA_SIZE : size);
    Send((char *)&pkt, sizeof(struct packet) - MAX_DATA_SIZE + size);
}

static void report_connect(void *p)
{
    set_timer(0);           // Stop Timer
    printf("Connected\n");
}

static void passive_con(void *p)
{
    send_packet(F_ACK, NULL, 0, -1);
    report_connect(NULL);
}

static void active_con(void *p)
{
    send_packet(F_CON, NULL, 0, -1);
    set_timer(CONNECT_TIMEOUT);
}

static void close_con(void *p)
{
    send_packet(F_FIN, NULL, 0, -1);
    printf("Connection Closed\n");
}

static void send_data(void *p)
{
    printf("Send Data to peer '%s' size:%d\n",
        ((struct p_event*)p)->packet.data, ((struct p_event*)p)->size);
    send_packet(F_DATA, (struct p_event *)p, ((struct p_event *)p)->size, packet_index);
    set_timer(CONNECT_TIMEOUT);
}

static void report_data(void *p)
{
	unsigned int idx = ((struct p_event*)p)->recv_packet.index;
	send_packet(F_ACK, NULL, 0, idx);
	if(stored_packet.index == idx){
		printf("Got same packet..\n");
	}
	else{
		printf("Data Arrived data='%s' size:%d\n",
				((struct p_event*)p)->recv_packet.data, ((struct p_event*)p)->recv_packet.size);
		stored_packet = ((struct p_event*)p)->recv_packet;
	}

}

static void data_success(void *p)
{
	set_timer(0);           // Stop Timer
	int idx = ((struct p_event*)p)->recv_packet.index;
	printf("data transfer complete : [%d].\n", idx);
	packet_index++;
}

struct state_action p_FSM[NUM_STATE][NUM_EVENT] = {
  //  for each event:
  //  RCV_CON,                 RCV_FIN,                 RCV_ACK,                       RCV_DATA,
  //  CONNECT,                 CLOSE,                   SEND,                          TIMEOUT

  // - wait_CON state
  {{ passive_con, CONNECTED }, { NULL, wait_CON },      { NULL, wait_CON },            { NULL, wait_CON },
   { active_con,  CON_sent },  { NULL, wait_CON },      { NULL, wait_CON },            { NULL, wait_CON }},

  // - CON_sent state
  {{ passive_con, CONNECTED }, { close_con, wait_CON }, { report_connect, CONNECTED }, { NULL,      CON_sent },
   { NULL,        CON_sent },  { close_con, wait_CON }, { NULL,           CON_sent },  { close_con, wait_CON }},

  // - CONNECTED state
  {{ NULL, CONNECTED },        { close_con, wait_CON }, { NULL,   CONNECTED }, { report_data, CONNECTED },
   { NULL, CONNECTED },        { close_con, wait_CON }, { send_data,      RETRANSMISSION }, { send_data, CONNECTED }},

  // - RETRANSMISSION state
  {{ NULL, RETRANSMISSION },   { close_con, wait_CON }, { data_success,  CONNECTED },  { report_data, RETRANSMISSION },
   { NULL, RETRANSMISSION },   { close_con, wait_CON }, { NULL,     RETRANSMISSION },  { send_data,   RETRANSMISSION }},

};



struct p_event *get_event(void) {
	static struct p_event event;    // not thread-safe

	loop:
	// Check if there is user command
	if (!kbhit()) {
		// Check if timer is timed-out
		if (timedout) {
			timedout = 0;
			event.event = TIMEOUT;
		}
		else {
			// Check Packet arrival by event_wait()
			ssize_t n = Recv((char*) &event.recv_packet, sizeof(struct packet));
			if (n > 0) {
				// if then, decode header to make event
				switch (event.recv_packet.type) {
				case F_CON:
					event.event = RCV_CON;
					break;
				case F_ACK:
					event.event = RCV_ACK;
					break;
				case F_FIN:
					event.event = RCV_FIN;
					break;
				case F_DATA:
					event.event = RCV_DATA;
					break;
					event.size = event.recv_packet.size;
					break;
				default:
					goto loop;
				}
			} else
				goto loop;
		}
	} else {
		int n = getchar();
		switch (n) {
		case '0':
			event.event = CONNECT;
			break;
		case '1':
			event.event = CLOSE;
			break;
		case '2':
			event.event = SEND;
			sprintf(event.packet.data, "%09d", data_count++);
			event.size = strlen(event.packet.data) + 1;
			break;
		case '3':
			return NULL;  // QUIT
		default:
			goto loop;
		}
	}
	return &event;
}

void Protocol_Loop(void) {
	struct p_event *eventp;

	timer_init();
	while (1) {
		printf("Current State = %s\n", st_name[c_state]);

		/* Step 0: Get Input Event */
		if ((eventp = get_event()) == NULL)
			break;
		printf("EVENT : %s\n", ev_name[eventp->event]);
		/* Step 1: Do Action */
		if (p_FSM[c_state][eventp->event].action)
			p_FSM[c_state][eventp->event].action(eventp);
		else
			printf("No Action for this event\n");

		/* Step 2: Set Next State */
		c_state = p_FSM[c_state][eventp->event].next_state;
	}
}

int main(int argc, char *argv[]) {
	ChannelNumber channel;
	ID id;
	int rateOfPacketLoss;

	printf("Channel : ");
	scanf("%d", &channel);
	printf("ID : ");
	scanf("%d", &id);
	printf("Rate of Packet Loss (0 ~ 100)%% : ");
	scanf("%d", &rateOfPacketLoss);
	if (rateOfPacketLoss < 0)
		rateOfPacketLoss = 0;
	else if (rateOfPacketLoss > 100)
		rateOfPacketLoss = 100;

	// Login to SIMULATOR

	if (Login(channel, id, rateOfPacketLoss) == -1) {
		printf("Login Failed\n");
		return -1;
	}

	printf("Entering protocol loop...\n");
	printf("type number '[0]CONNECT', '[1]CLOSE', '[2]SEND', or '[3]QUIT'\n");
	Protocol_Loop();

	// SIMULATOR_CLOSE

	return 0;
}

