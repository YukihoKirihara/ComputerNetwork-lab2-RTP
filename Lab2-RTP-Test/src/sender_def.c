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
#include "sender_def.h"

#define HEADER_SIZE         11      // the size of a rtp_header. 
#define PACKET_SIZE         1472    // the maximal size of a rtp_packet.
#define SHORT_BUF_SIZE      2048    // the length of a buffer for convenience.
#define MAX_WINDOW_SIZE     512     // the maximal size of a gliding window. 

#define TIMEOUT             100     // A timeout occurs if current time is not less than 100ms larger than the set time.
#define RECV_TIMEOUT        10*CLOCKS_PER_SEC   // The maximal time the receiver waits for a message.


typedef struct gliding_window {
    rtp_packet_t * p[MAX_WINDOW_SIZE];  // Use a circular array
    int acked[MAX_WINDOW_SIZE];         // Used in Selective Resend, Always 0 in Go Back N ?
    int head;   // Pointer to the head of the window. Mod curr_window_size when used.
    int tail;   // Pointer to the tail of the window. Usually tail = head-1 (mod N).
} gliding_window_t;

static gliding_window_t GW;
static uint32_t curr_window_size;
static int curr_socket_fd;
static struct sockaddr_in server_addr, reply_addr, client_addr;
static uint32_t curr_seq_num;
static clock_t set_time, curr_time;
static int addr_len = sizeof(struct sockaddr_in);

static void Init_Sender(void);
static int Resend_Window(void);
static int Selective_Resend(void);
static int Send_End_Message(void);
static void Free_Gliding_Window(void);
static uint32_t Checksum_Reconstruct(rtp_packet_t * pkt, size_t pkt_len);

static int Min(int x, int y) {
    return (x<y)?x:y;
}

/*
    Init_Sender
    In prevention of malicious testing without calling terminating function to clean the waste, 
        a throughout cleaning at the beginning is necessary.
*/
void Init_Sender(void) {
    Free_Gliding_Window();
    curr_window_size = 0;
    curr_socket_fd = 0;
    bzero(&server_addr, sizeof(server_addr));
    bzero(&client_addr, sizeof(client_addr));
    bzero(&reply_addr, sizeof(reply_addr));
    curr_seq_num = 0;
    set_time = curr_time = 0;
    addr_len = sizeof(struct sockaddr_in);
}

/*
    Sender is responsible for the reliable transmission in these cases:
        1. A packet loss at any level.
        2. Disordered arrival of ACK messages.
        3. Multi-receive of any number of any message.
        4. ACK message delay.
        5. Damaged message.
    A timer is needed to deal with DATA/ACK message loss.
    It is set when the gliding window moves, 
        and when it reaches 100ms, 
        all DATA message in the current window should be resent.
*/
/*
    initSender
    First, build the UDP socket.
    Second, sender send a message with type START and seq_num a random value. 
    Third, wait for the ACK message with the same seq_num.
        When it arrives, the connection is made.
    
    If the ACK message of START type is lost, 
        the sender determines a timeout (100ms). 
        (The receiver has created the connection, and is ready to receive data.)
        Therefore, the sender should send a message of END type.
    If the ACK message of START type is damaged,
        the sender should send a message of END type.
*/
int initSender(const char* receiver_ip, uint16_t receiver_port, uint32_t window_size) {
    Init_Sender();
    
    curr_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (curr_socket_fd == -1) {
        printf("Error: Failed to create the socket for sender.\n");
        printf("%s\n", strerror(errno));
        return -1;
    } 
    // Set the socket fd O_NONBLOCK so that it will not block on recvfrom().
    // int flags = fcntl(curr_socket_fd, F_GETFL);
    // flags |= O_NONBLOCK;
    // if (fcntl(curr_socket_fd, F_SETFL, flags) == -1) {
    //     printf("Error: Failed to set the socket for sender non-block.\n");
    //     printf("%s\n", strerror(errno));
    //     return -1;
    // }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(receiver_port);
    server_addr.sin_addr.s_addr = inet_addr(receiver_ip);
    curr_window_size = window_size;    

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    if (setsockopt(curr_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        printf("Error: Failed to set socket timeout.\n");
    }

    // getsockname(curr_socket_fd, (struct sockaddr *)&client_addr, &addr_len);
    // client_addr.sin_port = htons(23334);
    // client_addr.sin_family = AF_INET;
    // client_addr.sin_addr.s_addr = INADDR_ANY;
    // if (bind(curr_socket_fd, (struct sockaddr*)&client_addr, addr_len) == -1) {
    //     printf("Error: Failed to bind the socket to the address.\n");
    //     printf("%s\n", strerror(errno));
    //     return -1;
    // }

    rtp_packet_t * send_msg;
    uint32_t packet_len = 0;
    send_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
    send_msg->rtp.type = RTP_START;
    send_msg->rtp.length = 0;
    send_msg->rtp.seq_num = curr_seq_num = rand();
    // memset(send_msg->payload, 0, PAYLOAD_SIZE);
    packet_len = HEADER_SIZE+send_msg->rtp.length;
    send_msg->rtp.checksum = 0;
    send_msg->rtp.checksum = compute_checksum(send_msg, packet_len);

    int send_cnt = 0, send_num = 0;
    /* Assume that 
        if some error occurs before START message sending is completed, 
        no END message needs to be sent.
    */
    while (send_cnt < packet_len) {
        send_num = sendto(curr_socket_fd, (unsigned char *)send_msg, packet_len, 0, (struct sockaddr *)&server_addr, addr_len);
        if (send_num == -1) {
            printf("Error: Failed to send a message.\n");
            printf("%s\n", strerror(errno));
            free(send_msg); send_msg = NULL;
            return -1;
        }
        else if (send_num == 0) {
            printf("Error: Connection closed before sendto() finishes.\n");
            free(send_msg); send_msg = NULL;
            return -1;
        }
        else send_cnt += send_num;
    }
    free(send_msg); send_msg = NULL;
    // printf("START Message sent.\n");

    rtp_packet_t * recv_msg;
    recv_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
    uint8_t * recv_buf;
    recv_buf = (uint8_t *) malloc(SHORT_BUF_SIZE);
    int recv_num = 0, recv_cnt = 0;
    uint32_t recv_check = 0;
    set_time = clock();

//Wait_for_START_ACK:
while(1) {
    memset(recv_buf, 0, SHORT_BUF_SIZE);
    recv_num = 0;
    recv_cnt = 0;
    while (recv_cnt < HEADER_SIZE) {
        recv_num = recvfrom(curr_socket_fd, recv_buf, PACKET_SIZE, 0, (struct sockaddr *)&reply_addr, &addr_len);     
        curr_time = clock();
        if (recv_num == -1) {   // No data is waiting to be received.
            if (curr_time-set_time >= RECV_TIMEOUT) {  // A timeout occurs waiting for ACK. 
                printf("Timeout: The ACK for a START message is lost or damaged.\n");
                Send_End_Message();
                printf("RTP Connection terminated.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                return -1;
            }
        }
        else if (recv_num == 0) {   // The connection is closed.
            printf("Error: Connection closed before recvfrom() finishes.\n");
            free(recv_msg); recv_msg = NULL;
            free(recv_buf); recv_buf = NULL;
            // Then no way and no need to send END message.
            return -1;
        }
        else recv_cnt += recv_num;
    }
    for (int i=0; i<HEADER_SIZE; i++) 
        *((unsigned char *)recv_msg+i) = recv_buf[i];
    // Check the message
    if ((recv_msg->rtp.type == RTP_ACK) && (recv_msg->rtp.seq_num == curr_seq_num)) {
        recv_check = Checksum_Reconstruct(recv_msg, HEADER_SIZE);
        // if ((recv_msg->rtp.length == 0) && (recv_check == 0)) {
        //    printf("START message successfully sent and acknowledged.\n");
        // }
        if (recv_check != 0) {
            // printf("Warning: START ACK message checksum failure.\n");
            // goto Wait_for_START_ACK;
            continue;
        }
        else if (recv_msg->rtp.length != 0) 
            printf("Warning: START ACK message excessive length.\n");
        printf("RTP Connection starts.\n");
        free(recv_msg); recv_msg = NULL;
        free(recv_buf); recv_buf = NULL;
        return 0;
    }
    // else {// the message is not an ACK for curr_seq_num END message.
    //     goto Wait_for_START_ACK;
    // }
}
    // Control does not reach here
    free(recv_msg); recv_msg = NULL;
    free(recv_buf); recv_buf = NULL;
    return 0;

}


/*
    sendMessage
    Send the file named *message in the current directory, 
        return 0 if succeed and -1 if fail.  

    1. Read the file for utmost PAYLOAD_SIZE bytes.
    2. Packet it in a DATA message, and increment seq_num. 
    3. Apply a gliding window machinery for reliable transmission. 
        The number of files that is in flight and not yet acknowledged should not exceed window_size.
        Each DATA message is acknowledged by a ACK message, with the seq_num a message it expects to receive at that moment.
        When the first package in the window is acknowledged, 
            the window moves and set the timer.
        Message can be lost, delayed, damaged during transmission, 
            and multiple ACK and disorder may also happen.
        When the timer reaches 100ms, 
            RESEND ALL THE DATA MESSAGE IN THE WINDOW.
    4. Repeat 1 through 3 until the whole file is sent.        
    
    FSM
    <Send a DATA message>
        If the window reaches curr_window_size, skip.
        If the file sending is completed, skip.
    ↓
    <Try receiving an ACK message>
        Succeed ->  If ACK message valid, mark in the window 
                        If ACK seq_num >= window.head, move the window's head and reset the timer.
                    Else, do nothing.
        Failed ->   If Out of time, go to <Resend the whlole window>
                    Else, go to <Send a DATA message>
    
    <Resend the whole window>
*/
int sendMessage(const char* message) {
    FILE * localfile;   // The target file to send.
    int file_len = 0;  // Total bytes number to send in the file.
    int file_cnt = 0;   // Bytes number that has been sent in the file.
    localfile = fopen(message, "r");
    if (localfile == NULL) {
        printf("Error: Failed to open local file %s.\n", message);
        return -1;
    }
    fseek(localfile, 0, SEEK_END);
    file_len = ftell(localfile);
    fseek(localfile, 0, SEEK_SET);

    int pld_len = 0, packet_len = 0, send_cnt = 0, send_num = 0;
    int recv_cnt = 0, recv_num = 0, recv_seq_num = 0, recv_flag = 0;
    uint32_t recv_check = 0;
    rtp_packet_t * send_msg;
    rtp_packet_t * recv_msg;
    uint8_t * recv_buf;
    recv_buf = (uint8_t *) malloc(SHORT_BUF_SIZE);
    curr_seq_num = -1;
    GW.head = 0, GW.tail = -1;  // the gliding window = [head, tail]
    while (1) {
        // <Send a DATA message>
Send_DATA_Message:
        // Read and pack the message
        if ((GW.tail-GW.head+1 >= curr_window_size) || (file_cnt >= file_len)) 
            goto Recv_ACK_Message;
        GW.tail++;
        GW.p[GW.tail%curr_window_size] = (rtp_packet_t *) calloc(PACKET_SIZE, 1); 
        GW.acked[GW.tail%curr_window_size] = 0;
        send_msg = GW.p[GW.tail%curr_window_size];
        pld_len = Min(PAYLOAD_SIZE, file_len-file_cnt);
        packet_len = HEADER_SIZE+pld_len;
        if (fread(send_msg->payload, pld_len, 1, localfile) != 1) {
            printf("Error: Failed to read file %s at position %d.\n", message, ftell(localfile));
            fclose(localfile);
            Free_Gliding_Window();
            return -1;
        }
        send_msg->rtp.type = RTP_DATA;
        send_msg->rtp.length = pld_len;
        send_msg->rtp.seq_num = ++curr_seq_num;
        send_msg->rtp.checksum = 0;
        send_msg->rtp.checksum = compute_checksum(send_msg, packet_len);
        
        // printf("in the sender\n");
        // for (int i=0;i<HEADER_SIZE; i++) {
        //     printf("%02x ",*((unsigned char*)send_msg+i));
        // }
        // printf("\n");

        // Send the message
        send_cnt = 0; send_num = 0;
        while (send_cnt < packet_len) {
            send_num = sendto(curr_socket_fd, (unsigned char *)send_msg, packet_len, 0, (struct sockaddr *)&server_addr, addr_len);
            if (send_num == -1) {
                printf("Error: Failed to send a message.\n");
                printf("%s\n", strerror(errno));
                fclose(localfile);
                Free_Gliding_Window();
                return -1;
            }
            else if (send_num == 0) {
                printf("Error: Connection closed before sendto() finishes.\n");
                fclose(localfile);
                Free_Gliding_Window();
                return -1;
            }
            else send_cnt += send_num;
        }
        file_cnt += pld_len;
        if (GW.head == 0) 
            set_time = clock();         // the first message un-acknowledged

        // <Try receiving an ACK message>
Recv_ACK_Message:
        recv_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
        memset(recv_buf, 0, SHORT_BUF_SIZE);
        recv_num = 0;
        recv_cnt = 0;
        recv_flag = 0;
        // Try receiving a message
        recv_num = recvfrom(curr_socket_fd, recv_buf, PACKET_SIZE, 0, (struct sockaddr *)&reply_addr, &addr_len);
        if (recv_num == 0) {    // Connection closed.
            printf("Error: Connection closed before recvfrom() finishes.\n");
            free(recv_msg); recv_msg = NULL;
            free(recv_buf); recv_buf = NULL;
            fclose(localfile);
            Free_Gliding_Window();
            return -1;
        }
        else if (recv_num == -1) {   // No message for the time.
            curr_time = clock();
            if (curr_time-set_time >= RECV_TIMEOUT) {
                printf("Timeout: No message arrival.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                fclose(localfile);
                Free_Gliding_Window();
                return -1;
            }
            else if (curr_time-set_time >= TIMEOUT) {  // Timeout for the window head.
                if (Resend_Window() == -1) {
                    free(recv_msg); recv_msg = NULL;
                    free(recv_buf); recv_buf = NULL;
                    fclose(localfile);
                    Free_Gliding_Window();
                    return -1;
                }
                set_time = clock();
            }
            continue;
        }
        // Some message is received
        else recv_cnt += recv_num;
        if (recv_cnt < HEADER_SIZE)
            continue;
        // A full-size packet is received.
        for (int i=0; i<HEADER_SIZE; i++)
            *((unsigned char *)recv_msg+i) = recv_buf[i];
        if (recv_msg->rtp.type == RTP_ACK) {
            recv_check = Checksum_Reconstruct(recv_msg, recv_cnt);
            if (recv_cnt != HEADER_SIZE) {
                // printf("Warning: DATA ACK message excessive lengh.\n");
                continue;
            }
            if ((recv_msg->rtp.length == 0) && (recv_check == 0)) {
                // An ACK message is received. seq_num is the next message the receiver expects.
                if (recv_msg->rtp.seq_num > GW.p[GW.head%curr_window_size]->rtp.seq_num) {
                    if (recv_msg->rtp.seq_num-1 <= GW.p[GW.tail%curr_window_size]->rtp.seq_num) {
                        for (; GW.p[GW.head%curr_window_size] != NULL; GW.head++) {
                            if (GW.p[GW.head%curr_window_size]->rtp.seq_num >= recv_msg->rtp.seq_num) 
                                break;
                            GW.acked[GW.head%curr_window_size] = 1;
                            free(GW.p[GW.head%curr_window_size]); GW.p[GW.head%curr_window_size] = NULL;
                        }
                        set_time = clock();
                        recv_flag = 1;
                    }
                    // else {  
                    //     printf("Warning: DATA ACK message contains an invalid sequence number.\n");
                    // }
                }
                // Otherwise, the seq_num is out of date. Neglect.
            }
            // The following 2 cases are regarded as damaged packet. Neglect.
            // if (recv_check != 0) {
            //     printf("Warning: DATA ACK message checksum failure.\n");
            // }
            // else if (recv_msg->rtp.length != 0) {
            //     printf("Warning: DATA ACK message excessive length.\n");
            // }
        }
    
        // Complete the file send, when all data have been sent and acknowledged.
        if ((file_cnt == file_len) && (GW.head > GW.tail)) {
            break;
        }
    }

    free(recv_msg); recv_msg = NULL;
    free(recv_buf); recv_buf = NULL;
    fclose(localfile);
    Free_Gliding_Window();
    return 0;
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
    Resend_Window
    State <Resend the whole window> of FSM.
    When a timeout occurs, resend all the data messages in the current window.
    Return 0 if succeed, and -1 if failed.
*/
int Resend_Window(void) {
    // printf("Note: Resending the whole window.\n");
    int packet_len = 0, send_cnt = 0, send_num = 0;
    rtp_packet_t * send_msg;
    for (int i=GW.head; i<=GW.tail; i++) {
        if (GW.p[i%curr_window_size] == NULL)
            continue;
        if (GW.acked[i%curr_window_size] == 1) 
            continue;
        send_msg = GW.p[i%curr_window_size];
        packet_len = HEADER_SIZE+send_msg->rtp.length;
        send_cnt = 0;
        while (send_cnt < packet_len) {
            send_num = sendto(curr_socket_fd, (unsigned char *)(send_msg)+send_cnt, packet_len-send_cnt, 0, (struct sockaddr *)&server_addr, addr_len);
            if (send_num == -1) {
                // printf("Error: Failed to send a message.\n");
                // printf("%s\n", strerror(errno));
                return -1;
            }
            else if (send_num == 0) {
                // printf("Error: Connection closed before sendto() finishes.\n");
                return -1;
            }
            else send_cnt += send_num;
        }
        // break;
    }
    return 0;
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
    terminateSender
    Close RTP connection and close UDP socket.
    First, call Send_End_Message() to send a END message, and receive its ACK.
        Cases are that the connection may have been closed, 
            or the END ACK has a timeout...
        Returns 0 if the final result is correct.
        Returns -1 only if the END message is unable to send.
    Second, close the UDP socket.
*/
void terminateSender() {
    if (Send_End_Message() == -1) {
        printf("Error: Failed to terminate RTP Connection regularly.\n");
    }
    else 
        printf("RTP Connection terminated.\n");
    
    if (close(curr_socket_fd) == -1) {
        printf("Error: Failed to close UDP socket regularly.\n");
        printf("%s\n", strerror(errno));
        // Probably already closed.
    }
    else 
        printf("UDP socket closed.\n");
    // Clear up
    curr_window_size = 0;
    curr_socket_fd = -1;
    curr_seq_num = 0;
    bzero((char *)&server_addr, sizeof(server_addr));
    bzero((char *)&reply_addr, sizeof(reply_addr));
    set_time = curr_time = 0;
    return;
}


/*
    Send_End_Message
    // A special case for initSender(), called when an ACK for a START message is lost or damaged.
    Send a single END message.

    First, send an END message with its seq_num.
    Second, wait for its ACK;
        if a timeout occurs, terminate directly.
    Returns 0 if succeed, and -1 if an error occurs.
*/
int Send_End_Message(void) {
    rtp_packet_t * send_msg;
    uint32_t packet_len = 0;
    send_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
    send_msg->rtp.type = RTP_END;
    send_msg->rtp.length = 0;
    send_msg->rtp.seq_num = ++curr_seq_num;
    packet_len = HEADER_SIZE+send_msg->rtp.length;
    send_msg->rtp.checksum = 0;
    send_msg->rtp.checksum = compute_checksum(send_msg, packet_len);

    int send_cnt = 0, send_num = 0;
    while (send_cnt < packet_len) {
        send_num = sendto(curr_socket_fd, (unsigned char *)(send_msg)+send_cnt, packet_len-send_cnt, 0, (struct sockaddr *)&server_addr, addr_len);
        if (send_num == -1) {
            printf("Error: Failed to send an END message.\n");
            printf("%s\n", strerror(errno));
            free(send_msg); send_msg = NULL;
            return -1;
        }
        else if (send_num == 0) {
            printf("Error: Connection closed before sendto() finishes.\n");
            free(send_msg); send_msg = NULL;
            return 0;   // Afterall the connection is closed.
        }
        else send_cnt += send_num;
    }
    free(send_msg); send_msg = NULL;

    rtp_packet_t * recv_msg;
    recv_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
    uint8_t * recv_buf;
    recv_buf = (uint8_t *) malloc(SHORT_BUF_SIZE);
    int recv_num = 0, recv_cnt = 0;
    uint32_t recv_check = 0;
    set_time = clock();

Wait_for_END_ACK:
    recv_num = 0;
    recv_cnt = 0;
    while (recv_cnt < HEADER_SIZE) {
        recv_num = recvfrom(curr_socket_fd, recv_buf+recv_cnt, HEADER_SIZE-recv_cnt, 0, (struct sockaddr *)&reply_addr, &addr_len);
        curr_time = clock();
        if (recv_num == -1) {   // No data is waiting to be received.
            if (curr_time - set_time >= RECV_TIMEOUT) {  // A timeout occurs waiting for ACK.
                printf("Timeout: The ACK for a END message is lost or damaged.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                return 0;   // Terminate directly.
            }
        }
        else if (recv_num == 0) {   // The connection is closed.
            printf("Error: Connection closed before recvfrom() finishes.\n");
            free(recv_msg); recv_msg = NULL;
            free(recv_buf); recv_buf = NULL;
            return 0;
        }
        else recv_cnt += recv_num;
    }
    for (int i=0; i<HEADER_SIZE; i++) 
        *((unsigned char *)recv_msg+i) = recv_buf[i];
    // Check the message
    if ((recv_msg->rtp.type == RTP_ACK) && (recv_msg->rtp.seq_num == curr_seq_num)) {
        recv_check = Checksum_Reconstruct(recv_msg, HEADER_SIZE);
        // if ((recv_msg->rtp.length == 0) && (recv_check == 0)) 
        //     printf("END message successfully sent and acknowledged.\n");
        if (recv_check != 0) {
            // printf("Warning: END ACK message checksum failure.\n");
            goto Wait_for_END_ACK;
        }
        else if (recv_msg->rtp.length != 0) {
            // Read to clean the socket buffer.
            recv_num = recvfrom(curr_socket_fd, recv_buf, recv_msg->rtp.length, 0, (struct sockaddr *)&reply_addr, &addr_len);
            // printf("Warning: END ACK message excessive length.\n");
        }
        free(recv_msg); recv_msg = NULL;
        free(recv_buf); recv_buf = NULL;
        return 0;
    }
    else // the message is not an ACK for curr_seq_num END message.
        goto Wait_for_END_ACK;
    // Control does not reach here
    free(recv_msg); recv_msg = NULL;
    free(recv_buf); recv_buf = NULL;
    return 0;
}


/*
    sendMessageOpt
    An optimized version of sendMessage, with Selective Resending Machinery.
    Send the file named *message in the current directory, 
        return 0 if succeed and -1 if fail.

    Each ACK message is corresponded to a specific DATA message, with the same seq_num.
    When a Timeout occurs, only resend THOSE packets that have not yet been acknowledged.
*/
int sendMessageOpt(const char* message) {
    FILE * localfile;
    int file_len = 0;
    int file_cnt = 0;
    localfile = fopen(message, "r");
    if (localfile == NULL) {
        printf("Error: Failed to open local file %s.\n", message);
        return -1;
    }
    fseek(localfile, 0, SEEK_END);
    file_len = ftell(localfile);
    fseek(localfile, 0, SEEK_SET);

    Free_Gliding_Window();

    int pld_len = 0, packet_len = 0, send_cnt = 0, send_num = 0;
    int recv_cnt = 0, recv_num = 0, recv_seq_num = 0, recv_flag = 0;
    uint32_t recv_check = 0;
    rtp_packet_t * send_msg;
    rtp_packet_t * recv_msg;
    uint8_t * recv_buf;
    recv_buf = (uint8_t *) malloc(SHORT_BUF_SIZE);
    curr_seq_num = -1;
    GW.head = 0, GW.tail = -1;  // the gliding window = [head, tail]
    while (1) {
        // <Send a DATA message>
        if ((GW.tail-GW.head+1 < curr_window_size) && (file_cnt < file_len)) {
            GW.tail++;
            GW.p[GW.tail%curr_window_size] = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
            GW.acked[GW.tail%curr_window_size] = 0;
            send_msg = GW.p[GW.tail%curr_window_size];
            pld_len = Min(PAYLOAD_SIZE, file_len-file_cnt);
            packet_len = HEADER_SIZE+pld_len;
            if (fread(send_msg->payload, pld_len, 1, localfile) != 1) {
                printf("Error: Failed to read file %s at position %d.\n", message, ftell(localfile));
                fclose(localfile);
                Free_Gliding_Window();
                return -1;
            }
            send_msg->rtp.type = RTP_DATA;
            send_msg->rtp.length = pld_len;
            send_msg->rtp.seq_num = ++curr_seq_num;
            send_msg->rtp.checksum = 0;
            send_msg->rtp.checksum = compute_checksum(send_msg, packet_len);

            send_cnt = 0; send_num = 0;
            while (send_cnt < packet_len) {
                send_num = sendto(curr_socket_fd, (unsigned char *)send_msg, packet_len, 0, (struct sockaddr *)&server_addr, addr_len);
                if (send_num == -1) {
                    printf("Error: Failed to send a message.\n");
                    printf("%s\n", strerror(errno));
                    fclose(localfile);
                    Free_Gliding_Window();
                    return -1;
                }
                else if (send_num == 0) {
                    printf("Error: Connection closed before sendto() finishes.\n");
                    fclose(localfile);
                    Free_Gliding_Window();
                    return -1;
                }
                else send_cnt += send_num;
            }
            file_cnt += pld_len;
            if (GW.head == 0)
                set_time = clock();
        }

        // <Try receiving an ACK message>
        recv_msg = (rtp_packet_t *) calloc(PACKET_SIZE, 1);
        memset(recv_buf, 0, SHORT_BUF_SIZE);
        recv_num = 0; recv_cnt = 0; recv_flag = 0;
        recv_num = recvfrom(curr_socket_fd, recv_buf, PACKET_SIZE, 0, (struct sockaddr *)&reply_addr, &addr_len);
        if (recv_num == 0) {
            printf("Error: Connection closed before recvfrom() finishes.\n");
            free(recv_msg); recv_msg = NULL;
            free(recv_buf); recv_buf = NULL;
            fclose(localfile);
            Free_Gliding_Window();
            return -1;
        }
        else if (recv_num == -1) {
            curr_time = clock();
            if (curr_time-set_time >= RECV_TIMEOUT) {
                printf("Timeout: No message arrival.\n");
                free(recv_msg); recv_msg = NULL;
                free(recv_buf); recv_buf = NULL;
                fclose(localfile);
                Free_Gliding_Window();
                return -1;
            }
            else if (curr_time-set_time >= TIMEOUT) {
                if (Selective_Resend() == -1) {
                    free(recv_msg); recv_msg = NULL;
                    free(recv_buf); recv_buf = NULL;
                    fclose(localfile);
                    Free_Gliding_Window();
                    return -1;
                }
                set_time = clock();
            }
            continue;
        }
        // Some message is received
        else recv_cnt += recv_num;
        if (recv_cnt < HEADER_SIZE)
            continue;
        // A full-size packet is received.
        for (int i=0; i<HEADER_SIZE; i++) 
            *((unsigned char *)recv_msg + i) = recv_buf[i];
        if (recv_msg->rtp.type == RTP_ACK) {
            recv_check = Checksum_Reconstruct(recv_msg, recv_cnt);
            if (recv_cnt != HEADER_SIZE) {
                // printf("Warning: DATA ACK message excessive lengh.\n");
                continue;
            }
            if ((recv_msg->rtp.length == 0) && (recv_check == 0)) {
                if ((recv_msg->rtp.seq_num >= GW.p[GW.head%curr_window_size]->rtp.seq_num) && 
                    (recv_msg->rtp.seq_num <= GW.p[GW.tail%curr_window_size]->rtp.seq_num)) {
                    for (int iter = GW.head; iter <= GW.tail; iter++) {
                        if (GW.p[iter%curr_window_size] != NULL) {
                            if (GW.p[iter%curr_window_size]->rtp.seq_num == recv_msg->rtp.seq_num) 
                                GW.acked[iter%curr_window_size] = 1;
                        }
                    }
                    recv_flag = 1;
                    while ((GW.head <= GW.tail) && (GW.p[GW.head%curr_window_size] != NULL)) {
                        if (GW.acked[GW.head%curr_window_size] != 1) 
                            break;
                        free(GW.p[GW.head%curr_window_size]); GW.p[GW.head%curr_window_size] = NULL;
                        GW.head++; 
                    }
                    set_time = clock();
                }
            }
            // if (recv_check != 0) {
            //     printf("Warning: DATA ACK message checksum failure.\n");
            // }
            // else if (recv_msg->rtp.length != 0){
            //     printf("Warning: DATA ACK message excessive length.\n");
            // }
        }

        if ((file_cnt == file_len) && (GW.head > GW.tail)) 
            break;
    }

    free(recv_msg); recv_msg = NULL;
    free(recv_buf); recv_buf = NULL;
    fclose(localfile);
    Free_Gliding_Window();
    return 0;
}


/*
    Selective_Resend
    When a timeout occurs, resend all the packets in the gliding window 
        that has not yet been acknowledged.
    Return 0 if succeed, and -1 if failed.
*/
static int Selective_Resend(void) {
    // printf("Note: Selective Resending of the window.\n");
    int packet_len = 0, send_cnt = 0, send_num = 0;
    rtp_packet_t * send_msg;
    for (int i=GW.head; i<=GW.tail; i++) {
        if (GW.p[i%curr_window_size] == NULL) 
            continue;
        if (GW.acked[i%curr_window_size] == 1) 
            continue;
        send_msg = GW.p[i%curr_window_size];
        packet_len = HEADER_SIZE+send_msg->rtp.length;
        send_cnt = 0;
        while (send_cnt < packet_len) {
            send_num = sendto(curr_socket_fd, (unsigned char *)(send_msg)+send_cnt, packet_len-send_cnt, 0, (struct sockaddr *)&server_addr, addr_len);
            if (send_num == -1) {
                printf("Error: Failed to send a message.\n");
                printf("%s\n", strerror(errno));
                return -1;
            }
            else if (send_num == 0) {
                printf("Error: Connection closed before sendto() finishes.\n");
                return -1;
            }
            else send_cnt += send_num;
        }
        // break;
    }
    return 0;
}
