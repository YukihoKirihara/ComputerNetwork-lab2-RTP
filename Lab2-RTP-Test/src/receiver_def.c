// Network
#include<unistd.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<errno.h>
#include<malloc.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<stdarg.h>
#include<fcntl.h>
// Process
#include<sys/wait.h>
#include<sys/ipc.h>
#include<sys/shm.h>
#include<signal.h>
// Thread
#include<pthread.h>
#include<sys/poll.h>    // link thread when compiling "-lthread"
#include<sys/time.h>
#include<sys/epoll.h>

#include "util.h"
#include "rtp.h"
#include "receiver_def.h"

#define HEADER_SIZE         11      // the size of a rtp_header. 
#define PACKET_SIZE         1472    // the maximal size of a rtp_packet.
#define SHORT_BUF_SIZE      2048    // the length of a buffer for convenience.
#define MAX_WINDOW_SIZE     512     // the maximal size of a gliding window. 

#define TIMEOUT             100     // A timeout occurs if current time is not less than 100ms larger than the set time.
#define RECV_TIMEOUT        4*CLOCKS_PER_SEC   // The maximal time the receiver waits for a message.


typedef struct gliding_window {
    rtp_packet_t * p[MAX_WINDOW_SIZE];  // Use a circular array
    int acked[MAX_WINDOW_SIZE];         // Used in Selective Resend, Always 0 in Go Back N ?
    int head;   // Pointer to the head of the window. Mod curr_window_size when used.
    int tail;   // Pointer to the tail of the window. Usually tail = head-1 (mod N).
} gliding_window_t;

static gliding_window_t GW;
static uint32_t curr_window_size;
static int listen_socket_fd;
static struct sockaddr_in server_addr, client_addr;
static clock_t set_time, curr_time;
static int addr_len = sizeof(server_addr);
static int started;     // A START message has been received, and a RTP Connection on-going. Used to identify multiple START's.
static uint32_t expc_seq_num;       // Expected sequence number of DATA message.

static void Init_Receiver(void);
static void Free_Gliding_Window(void);
static int Send_ACK_Message(uint32_t seq_num);
static uint32_t Checksum_Reconstruct(rtp_packet_t * pkt, size_t pkt_len);

static int Min(int x, int y) {
    return (x<y)?x:y;
}

/*
    Init_Receiver
    In prevention of malicious testing without calling terminating function to clean the waste, 
        a throughout cleaning at the beginning is necessary.
*/
void Init_Receiver(void) {
    Free_Gliding_Window();
    curr_window_size = 0;
    listen_socket_fd = 0;
    bzero(&server_addr, sizeof(server_addr));
    bzero(&client_addr, sizeof(client_addr));
    set_time = curr_time = 0;
    addr_len = sizeof(struct sockaddr_in);
    started = 0;
    expc_seq_num = 0;
}

/*
    initReceiver
    Open the receiver, listen and wait for connection on port of all IPs.
    Return 0 if succeed, -1 if failed. 
    
*/
int initReceiver(uint16_t port, uint32_t window_size) {
    Init_Receiver();

    listen_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_socket_fd == -1) {
        printf("Error: Failed to create the listen socket for receiver.\n");
        printf("%s\n", strerror(errno));
        return -1;
    } 
    int flags = fcntl(listen_socket_fd, F_GETFL);
    flags |= O_NONBLOCK;
    if (fcntl(listen_socket_fd, F_SETFL, flags) == -1) {
        printf("Error: Failed to set the listen socket for the receiver non-block.\n");
        printf("%s\n", strerror(errno));
        return -1;
    }
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;
    curr_window_size = window_size;
    /*
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;    // 100 ms == TIMEOUT
    if (setsockopt(listen_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        printf("Error: Failed to set socket timeout.\n");
    }
    */
    
    if (bind(listen_socket_fd, (struct sockaddr*)&server_addr, addr_len) == -1) {
        printf("Error: Failed to bind the listen socket to the address.\n");
        printf("%s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/*
    recvMessage
    Receive data and close RTP connection when finished.
    Return the byte number of data if succeed, and -1 if failed.

    1. Receive a header and its payload.
        Since the checksum has not yet been verified, 
            chances are that the length is malicious, and a prevention of over-reading is needed.
    2. Verify its checksum, 
        if it is erroneous, 
            if it is a START message, return -1, 
            else, neglect the message.
        else to 3.
    3. If it is a START message, 
        if this is the first START message, 
            start the RTP Connection and reply an ACK.
        else (duplicate START) neglect.
       If any DATA/END/ACK message arrives before a START message, neglect.
    4. If it is a ACK message, neglect.
    5. If it is a DATA message, 
        store the payload and reply an ACK.
    6. If it is a END message, 
        terminate the RTP connection and reply an ACK.
        (Should the UDP socket also get closed?)

    Note: All the "neglect" must read the payload to clean the waste.

    DATA message management -- Optimized Go Back N

    If the seq_num < expc_seq_num || seq_num >= expc_seq_num + curr_wondow_size,
        neglect.
    If the expc_seq_num <= seq_num < expc_seq_num + curr_wondow_size, 
        cache the payload.
        If the expc_seq_num == seq_num, 
            store the consecutive messages' payloads into localfile, 
            update the gliding window and expc_seq_num, 
                so that the head of the gliding window is correspondent to the expc_seq_num. 
        send back expc_seq_num.

    The gliding window: [head, tail)

*/
int recvMessage(char* filename) {
    int file_len = 0, file_cnt = 0;

    FILE * localfile = fopen(filename, "w+");
    if (localfile == NULL) {
        printf("Error: Failed to open file %s.\n", filename);
        printf("%s\n", strerror(errno));
        return -1;
    }

    rtp_packet_t * recv_msg;
    recv_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
    uint8_t * recv_buf;
    recv_buf = (uint8_t *) malloc(SHORT_BUF_SIZE);
    int recv_num = 0, recv_cnt = 0, pld_len = 0, packet_len = 0;
    uint32_t recv_check = 0;
    set_time = curr_time = clock();

    int data_flag = 0;  // The first DATA message arrives, initialize the gliding window.

//Wait_for_DATA:
    while (1) {
        bzero(recv_msg, PACKET_SIZE);
        memset(recv_buf, 0, SHORT_BUF_SIZE);
        recv_num = 0;
        recv_cnt = 0;
        while (recv_num < HEADER_SIZE) {
            // PACKET_SIZE or SHORT_BUG_SIZE? Will it affect the next packet?
            recv_num = recvfrom(listen_socket_fd, recv_buf, PACKET_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
            if (recv_num == -1) {
                curr_time = clock();
                if (curr_time-set_time >= RECV_TIMEOUT) {
                    // printf("Timeout: No DATA message arrival.\n");
                    free(recv_msg); recv_msg = NULL;
                    free(recv_buf); recv_buf = NULL;
                    fclose(localfile);
                    return -1;
                }
            }
            else if (recv_num == 0) {
                // printf("Error: Connection closed befoe recvfrom() finishes.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                fclose(localfile);
                return -1;
            }
            else recv_cnt += recv_num;
        }
        if (recv_cnt < HEADER_SIZE) 
            continue;
        for (int i=0; i<HEADER_SIZE; i++) {
            *((unsigned char *)recv_msg+i) = recv_buf[i];
            // printf("%02x\n",recv_buf[i]);
        }
        recv_cnt = Min(recv_cnt, PACKET_SIZE);
        pld_len = recv_cnt-HEADER_SIZE;
        if (pld_len != recv_msg->rtp.length) {
            // printf("Warning: Discrepancy between the length of a received payload and its description in the header.\n");
            // printf("recv_cnt = %d, pld_len = %d\n", recv_cnt, pld_len);
            set_time = clock();
            continue;
        }
        if (pld_len > 0) {
            for (int i=0; i<pld_len; i++) 
                recv_msg->payload[i] = recv_buf[i+HEADER_SIZE];
        }
        // Check the header checksum

        // printf("in the receiver\n");
        // for (int i=0;i<HEADER_SIZE; i++) {
        //     printf("%02x ",*((unsigned char*)recv_msg+i));
        // }
        // printf("\n");

        packet_len = recv_cnt;
        recv_check = Checksum_Reconstruct(recv_msg, packet_len);
        if (recv_check != 0) {
            // printf("Warning: Message checksum failure. Packet to be discard.\n");
            if (recv_msg->rtp.type == RTP_START) {
                // printf("Error: START message checksum failure. Close the RTP Connectionn.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                fclose(localfile);
                return -1;
            }
            set_time = clock();
            continue;
        }    
        // A valid packet is received.
        // Dispatch according to its category.
        if (recv_msg->rtp.type == RTP_START) {
            // printf("recvmsg RTP_START.\n");
            if (started) {
                // printf("Warning: A START message arrived but an RTP Connection is already on operation.\n");
                set_time = clock();
                continue;
            }
            started = 1;
            data_flag = 0;
            expc_seq_num = 0;
            // printf("An RTP Connection started, with the client IP %s and port %d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            // START ACK
            if (Send_ACK_Message(recv_msg->rtp.seq_num) == -1) {
                printf("Error: Failed to send a START ACK message.\n");
            } 
            set_time = clock();
        }
        else if (recv_msg->rtp.type == RTP_ACK) {
            // printf("Receive message RTP_ACK.\n");
            // if (started == 0) 
            //     printf("Warning: An ACK message arrived before an RTP Connection is started.\n");
            // printf("Warning: An ACK type message arrived, which is undefined behavior.\n");
            set_time = clock();
        }
        else if (recv_msg->rtp.type == RTP_DATA){
            // printf("Receive message RTP_DATA.\n");
            if (started == 0) {
                // printf("Warning: A DATA message arrived before an RTP Connection is started.\n");
                set_time = clock();
                continue;
            }
            if (data_flag == 0) {   // Initialise the GW
                GW.head = 0;
                GW.tail = GW.head + curr_window_size;
                data_flag = 1;
            }
            if (recv_msg->rtp.seq_num >= expc_seq_num+curr_window_size) {
                // printf("Note: A DATA message neglected for un-needed sequence number %d.\n", recv_msg->rtp.seq_num);
                set_time = clock();
                continue;
            }
            if (recv_msg->rtp.seq_num < expc_seq_num) {
                // If the message has already arrived but not yet been acknowledged successfully. Also send an ACK message.
                if (Send_ACK_Message(expc_seq_num) == -1) {
                    printf("Error: Failed to send a DATA ACK message.\n");
                }
                set_time = clock();
                continue;
            }
            uint32_t iter = recv_msg->rtp.seq_num;
            if (GW.p[iter%curr_window_size] == NULL) {
                GW.p[iter%curr_window_size] = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
                for (int i=0; i<packet_len; i++) 
                    *((unsigned char *)GW.p[iter%curr_window_size]+i) = *((unsigned char *)recv_msg+i);  // Deep Copy is a must.
                GW.acked[iter%curr_window_size] = 1;
            }
            // Otherwise, this is a duplicate message. neglect.
            while (GW.p[GW.head%curr_window_size] != NULL) {
                if ((GW.p[GW.head%curr_window_size]->rtp.seq_num != expc_seq_num) || (GW.acked[GW.head%curr_window_size] != 1)) 
                    break; 
                if ((file_cnt = fwrite(GW.p[GW.head%curr_window_size]->payload, GW.p[GW.head%curr_window_size]->rtp.length, 1, localfile)) != 1) {
                    // printf("Error: Failed to write into file %s.\n", filename);
                    fclose(localfile);
                    free(recv_msg); recv_msg = NULL;
                    free(recv_buf); recv_buf = NULL;
                    Free_Gliding_Window();
                    terminateReceiver();
                    return -1;
                }
                file_len += file_cnt;
                free(GW.p[GW.head%curr_window_size]); GW.p[GW.head%curr_window_size] = NULL;
                GW.acked[GW.head%curr_window_size] = 0;
                expc_seq_num++;
                GW.head++;
            }
            GW.tail = GW.head + curr_window_size;
            if (Send_ACK_Message(expc_seq_num) == -1) {
                printf("Error: Failed to send a DATA ACK message.\n");
            } 
            set_time = clock();
        }
        else if (recv_msg->rtp.type == RTP_END) {
            printf("Receive message RTP_END.\n");
            if (started == 0) {
                // printf("Warning: An END message arrived before an RTP Connection is started.\n");
                set_time = clock();
                continue;
            }
            if (Send_ACK_Message(recv_msg->rtp.seq_num) == -1) {
                printf("Error: Failed to send an END ACK message.\n");
            } 
            set_time = clock();
            free(recv_msg); recv_msg = NULL;
            free(recv_buf); recv_buf = NULL;
            fclose(localfile);
            // terminateReceiver();
            return file_len;
        }
        else {
            // printf("Warning: A message with unknown type arrived.\n");
            set_time = clock();
        }
    }

    return file_len;
}


/*
    Checksum_Reconstruct
    Return 0 if the checksum is valid, and a positive value if not.
*/
static uint32_t Checksum_Reconstruct(rtp_packet_t * pkt, size_t pkt_len) {
    uint32_t org_checksum = pkt->rtp.checksum;
    pkt->rtp.checksum = 0;
    uint32_t new_checksum = compute_checksum(pkt, pkt_len);
    pkt->rtp.checksum = org_checksum;
    return (org_checksum == new_checksum)? 0 : new_checksum;
}


/*
    Send_ACK_Message
    Send an ACK message with designated seq_num.
        The seq_num for START ACK and END ACK should be the same of the received message;
        while the seq_num for DATA ACK should be that of the message you expect to receive (the nearest un-arrived).
    Return 0 if succeed and -1 if failed.
*/
int Send_ACK_Message(uint32_t seq_num){
    rtp_packet_t * send_msg;
    int packet_len = 0, send_cnt = 0, send_num = 0;
    send_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
    send_msg->rtp.type = RTP_ACK;
    send_msg->rtp.length = 0;
    send_msg->rtp.seq_num = seq_num;
    send_msg->rtp.checksum = 0;
    packet_len = HEADER_SIZE;
    send_msg->rtp.checksum = compute_checksum(send_msg, packet_len);

    send_cnt = 0, send_num = 0;
    while (send_cnt < packet_len) {
        send_num = sendto(listen_socket_fd, (char *)(send_msg)+send_cnt, packet_len-send_cnt, 0, (struct sockaddr *)&client_addr, addr_len);
        if (send_num == -1) {
            // printf("Error: Failed to send a message.\n");
            // printf("%s\n", strerror(errno));
            free(send_msg); send_msg = NULL;
            return -1;
        }
        else if (send_num == 0) {
            // printf("Error: Connection closed before sendto() finishes.\n");
            free(send_msg); send_msg = NULL;
            return -1;
        }
        else send_cnt += send_num;
    }
    free(send_msg); send_msg = NULL;    
    return 0;
}


/*
    terminateReceiver
    When recvMessage() fails, call this function to close RTP connection and UDP socket. 
*/
void terminateReceiver() {
    // printf("RTP Connection terminated.\n");
    if (close(listen_socket_fd) == -1) {
        printf("Error: Failed to close UDP listen socket regularly.\n");
        printf("%s\n", strerror(errno));
    }
    else 
        printf("receiver: UDP socket closed.\n");
    curr_window_size = 0;
    listen_socket_fd = -1;
    expc_seq_num = 0;
    set_time = curr_time = 0;
    started = 0;
    bzero((char *)&server_addr, sizeof(server_addr));
    bzero((char *)&client_addr, sizeof(client_addr));
    return;
}

/*
    Free_Gliding_Window
    Reinitialization. Free the rtp_packets in the window.
*/
void Free_Gliding_Window(void) {
    for (int i=0; i<MAX_WINDOW_SIZE; i++) 
        if (GW.p[i] != NULL) {
            free(GW.p[i]); GW.p[i] = NULL;
        }
    memset(GW.acked, 0, MAX_WINDOW_SIZE);
    GW.head = 0;
    GW.tail = 0;
}


/*
    recvMessageOpt
    An optimized version of recvMessage, with Selective Resending Machinery. 
    The seq_num of a DATA ACK is that of the DATA message.
*/
int recvMessageOpt(char* filename) {
    int file_len = 0, file_cnt = 0;
    
    FILE * localfile = fopen(filename, "w+");
    if (localfile == NULL) {
        printf("Error: Failed to open file %s.\n", filename);
        printf("%s\n", strerror(errno));
        return -1;
    }

    rtp_packet_t * recv_msg;
    recv_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
    uint8_t * recv_buf;
    recv_buf = (uint8_t *) malloc(SHORT_BUF_SIZE);
    int recv_num = 0, recv_cnt = 0, pld_len = 0, packet_len = 0;
    uint32_t recv_check = 0;
    set_time = curr_time = clock();
    int data_flag = 0;

    Free_Gliding_Window();

    while (1) {
        bzero(recv_msg, PACKET_SIZE);
        memset(recv_buf, 0, SHORT_BUF_SIZE);
        recv_num = 0; recv_cnt = 0;
        // Some message is received.
        while (recv_num < HEADER_SIZE) {
            recv_num = recvfrom(listen_socket_fd, recv_buf, PACKET_SIZE, 0, (struct sockaddr *)&client_addr, &addr_len);
            if (recv_num == -1) {
                curr_time = clock();
                if (curr_time-set_time >= RECV_TIMEOUT) {
                    // printf("Timeout: No DATA message arrival.\n");
                    free(recv_msg); recv_msg = NULL;
                    free(recv_buf); recv_buf = NULL;
                    fclose(localfile);
                    return -1;
                }
            }
            else if (recv_num == 0) {
                // printf("Error: Connection closed befoe recvfrom() finishes.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                fclose(localfile);
                return -1;
            }
            else recv_cnt += recv_num;
        }
        if (recv_cnt < HEADER_SIZE) 
            continue;
        // A full packet is received.
        for (int i=0; i<HEADER_SIZE; i++) 
            *((unsigned char *)recv_msg + i) = recv_buf[i];
        recv_cnt = Min(recv_cnt, PACKET_SIZE);
        pld_len = recv_cnt-HEADER_SIZE;
        if (pld_len != recv_msg->rtp.length) {
            // printf("Warning: Discrepancy between the length of a received payload and its description in the header.\n");
            // printf("recv_cnt = %d, pld_len = %d\n", recv_cnt, pld_len);
            set_time = clock();
            continue;
        }
        if (pld_len > 0) {
            for (int i=0; i<pld_len; i++) 
                recv_msg->payload[i] = recv_buf[i+HEADER_SIZE];
        }

        // Verify the Checksum
        packet_len = recv_cnt;
        recv_check = Checksum_Reconstruct(recv_msg, packet_len);
        if (recv_check != 0) {
            // printf("Warning: Message checksum failure. Packet to be discard.\n");
            if (recv_msg->rtp.type == RTP_START) {
                // printf("Error: START message checksum failure. Close the RTP Connectionn.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                fclose(localfile);
                return -1;
            }
            set_time = clock();
            continue;
        }
        // A valid packet is received.
        // Dispatch according to its category.
        if (recv_msg->rtp.type == RTP_START) {
            // printf("recvmsg RTP_START.\n");
            if (started) {
                // printf("Warning: A START message arrived but an RTP Connection is already on operation.\n");
                set_time = clock();
                continue;
            }
            started = 1;
            data_flag = 0;
            expc_seq_num = 0;
            // printf("An RTP Connection started, with the client IP %s and port %d.\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            // START ACK
            if (Send_ACK_Message(recv_msg->rtp.seq_num) == -1) {
                printf("Error: Failed to send a START ACK message.\n");
            } 
            set_time = clock();
        }
        else if (recv_msg->rtp.type == RTP_ACK) {
            // printf("Receive message RTP_ACK.\n");
            // if (started == 0) 
                // printf("Warning: An ACK message arrived before an RTP Connection is started.\n");
            // printf("Warning: An ACK type message arrived, which is undefined behavior.\n");
            set_time = clock();
        }
        else if (recv_msg->rtp.type == RTP_DATA) {
            if (started == 0) {
                // printf("Warning: A DATA message arrived before an RTP Connection is started.\n");
                set_time = clock();
                continue;
            }
            if (data_flag == 0) {
                GW.head = 0;
                GW.tail = GW.head+curr_window_size;     //The gliding window: [head, tail)
                data_flag = 1;
            }
            if (recv_msg->rtp.seq_num >= expc_seq_num+curr_window_size) {
                set_time = clock();
                continue;
            }
            if (recv_msg->rtp.seq_num < expc_seq_num) {
                if (Send_ACK_Message(recv_msg->rtp.seq_num) == -1) {
                    printf("Error: Failed to send a DATA ACK message.\n");
                }
                set_time = clock();
                continue;
            }
            uint32_t iter = recv_msg->rtp.seq_num;
            if (GW.p[iter%curr_window_size] == NULL) {
                GW.p[iter%curr_window_size] = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
                for (int i=0; i<packet_len; i++) 
                    *((unsigned char *)GW.p[iter%curr_window_size]+i) = *((unsigned char *)recv_msg + i);
                GW.acked[iter%curr_window_size] = 1;
            }
            while (GW.p[GW.head%curr_window_size] != NULL) {
                if ((GW.p[GW.head%curr_window_size]->rtp.seq_num != expc_seq_num) || (GW.acked[GW.head%curr_window_size] != 1)) 
                    break;
                if ((file_cnt = fwrite(GW.p[GW.head%curr_window_size]->payload, GW.p[GW.head%curr_window_size]->rtp.length, 1, localfile)) != 1) {
                    // printf("Error: Failed to write into file %s.\n", filename);
                    fclose(localfile);
                    free(recv_msg); recv_msg = NULL;
                    free(recv_buf); recv_buf = NULL;
                    Free_Gliding_Window();
                    terminateReceiver();
                    return -1;
                }
                file_len += file_cnt;
                free(GW.p[GW.head%curr_window_size]); GW.p[GW.head%curr_window_size] = NULL;
                GW.acked[GW.head%curr_window_size] = 0;
                expc_seq_num ++;
                GW.head++;
            }
            GW.tail = GW.head + curr_window_size;
            if (Send_ACK_Message(recv_msg->rtp.seq_num) == -1) {
                printf("Error: Failed to send a DATA ACK message.\n");
            }
            set_time = clock();
        }
        else if (recv_msg->rtp.type == RTP_END) {
            // printf("Receive message RTP_END.\n");
            if (started == 0) {
                // printf("Warning: An END message arrived before an RTP Connection is started.\n");
                set_time = clock();
                continue;
            }
            if (Send_ACK_Message(recv_msg->rtp.seq_num) == -1) {
                printf("Error: Failed to send an END ACK message.\n");
            } 
            set_time = clock();
            free(recv_msg); recv_msg = NULL;
            free(recv_buf); recv_buf = NULL;
            fclose(localfile);
            // terminateReceiver();
            return file_len;
        }
        else {
            // printf("Warning: A message with unknown type arrived.\n");
            set_time = clock();
        }
    }

    return file_len;
}
