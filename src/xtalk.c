/***********************************************
 * XTALK COMMAND LINE ADAPTER
 * ---------------------------------------------
 * 24/08/2019 | v0.1.1 | by alimahouk
 * ---------------------------------------------
 * This utility acts as a wrapper for standard
 * Unix commands that output text. It reads
 * from standard input and sends it to xTalk.
 * 
 * The code currently only compiles on Unix-like
 * systems. Changes are needed to support the
 * Winsock API.
 *
 * Usage: This tool accepts two optional
 * arguments.
 * 
 * --re[-r]     The identifier of the message 
 *              being replied to.
 * --to[-t]     service@user
 *
 * After invoking the utility, enter your message
 * and press the Return key. You may also pass a
 * message from another program via standard input
 * if you wish.
 **********************************************/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#define XTALK_ADDR              "127.0.0.1"
#define XTALK_PORT              "1993"
#define LINE_TERM               "\r\n"
#define MAX_MESSAGE_LEN         141
#define MAX_RESPONSE_LEN        69
#define PROTO_KEY_PAYLOAD       "body"
#define PROTO_KEY_RECIPIENT     "to"
#define PROTO_KEY_REPLY_TO      "re"
#define USAGE_DESCRIPTION       "Usage: This tool accepts two optional arguments.\n\n" \
                                "--to[-t]\tservice@user\n" \
                                "--re[-r]\tThe identifier of the message being replied to.\n\n" \
                                "After invoking the utility, enter your message and press the Return key. " \
                                "You may also pass a message from another program via standard input if you wish.\n"


void crash(const char *err_message)
{
        fprintf(stderr, "%s", err_message);
        exit(1);
}

/**
 * Get sockaddr, IPv4 or IPv6.
 */
void *get_in_addr(struct sockaddr *sa)
{
        if (sa->sa_family == AF_INET)
                return &(((struct sockaddr_in *)sa)->sin_addr);

        return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void send_message(const char *recipient,
                  const char *in_reply_to,
                  const char *payload)
{
        struct addrinfo *server_info;
        struct addrinfo *p;
        struct addrinfo hints;
        char *in_reply_to_message;
        char *payload_message;
        char *recipient_message;
        char server[INET6_ADDRSTRLEN];
        char server_response[MAX_MESSAGE_LEN] = {0};
        int getaddrinfo_ret;
        int in_reply_to_size;
        int payload_size;
        int recipient_size;
        int sock_fd;
        int total_recv_bytes;

        recipient_message = NULL;
        recipient_size = 0;
        if (recipient)
        {
                recipient_size = snprintf(NULL, 0, "%s: %s", PROTO_KEY_RECIPIENT, recipient);
                recipient_message = (char *)calloc(recipient_size + 1, sizeof(char));
                snprintf(recipient_message, recipient_size + 1, "%s: %s", PROTO_KEY_RECIPIENT, recipient);
        }

        in_reply_to_message = NULL;
        in_reply_to_size = 0;
        if (in_reply_to)
        {
                in_reply_to_size = snprintf(NULL, 0, "%s: %s", PROTO_KEY_REPLY_TO, in_reply_to);
                in_reply_to_message = (char *)calloc(in_reply_to_size + 1, sizeof(char));
                snprintf(in_reply_to_message, in_reply_to_size + 1, "%s: %s", PROTO_KEY_REPLY_TO, in_reply_to);
        }

        payload_size = snprintf(NULL, 0, "%s: %s", PROTO_KEY_PAYLOAD, payload);
        payload_message = (char *)calloc(payload_size + 1, sizeof(char));
        snprintf(payload_message, payload_size + 1, "%s: %s", PROTO_KEY_PAYLOAD, payload);

        total_recv_bytes = 0;
        getaddrinfo_ret = 0;
        sock_fd = 0;
        
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        if ((getaddrinfo_ret = getaddrinfo(XTALK_ADDR, XTALK_PORT, &hints, &server_info)) != 0)
        {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(getaddrinfo_ret));
                exit(1);
        }

        // Loop through all the results and connect to the first we can.
        for (p = server_info; p != NULL; p = p->ai_next)
        {
                if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
                {
                        perror("client: socket");
                        continue;
                }

                if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1)
                {
                        close(sock_fd);
                        perror("client: connect");
                        continue;
                }
                break;
        }

        if (!p)
                crash("Failed to connect to xTalk!\n");

        inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), server, sizeof(server));
        freeaddrinfo(server_info);

        if (recipient_message)
        {
                write(sock_fd, recipient_message, strlen(recipient_message));
                write(sock_fd, LINE_TERM, strlen(LINE_TERM));
        }

        if (in_reply_to_message)
        {
                write(sock_fd, in_reply_to_message, strlen(in_reply_to_message));
                write(sock_fd, LINE_TERM, strlen(LINE_TERM));
        }

        write(sock_fd, payload_message, strlen(payload_message));
        write(sock_fd, LINE_TERM, strlen(LINE_TERM));
        write(sock_fd, LINE_TERM, strlen(LINE_TERM));

        if ((total_recv_bytes = recv(sock_fd, server_response, MAX_RESPONSE_LEN, 0)) == -1)
                crash("recv");

        server_response[total_recv_bytes] = '\0';
        close(sock_fd);
        // Print the receipt.
        printf("%s\n", server_response);
}

int main(int argc,
         char *argv[])
{
        char *recipient;
        char *in_reply_to;
        char payload[MAX_MESSAGE_LEN] = {0};
        int total_read_bytes;

        if (argc != 1 && argc != 3 && argc != 5)
                crash(USAGE_DESCRIPTION);

        recipient = NULL;
        in_reply_to = NULL;
        for (int i = 1; i < argc; i += 2)
        {
                char *argf;
                char *val;

                argf = argv[i];
                val = argv[i + 1];
                if (strcmp(argf, "-r") == 0 || strcmp(argf, "--re") == 0)
                        in_reply_to = val;
                else if (strcmp(argf, "-t") == 0 || strcmp(argf, "--to") == 0)
                        recipient = val;
                else
                        crash(USAGE_DESCRIPTION);
        }

        total_read_bytes = read(STDIN_FILENO, payload, MAX_MESSAGE_LEN - 1);
        if (total_read_bytes < 0)
                return -1;
        
        payload[total_read_bytes] = '\0';
        send_message(recipient, in_reply_to, payload);

        return 0;
}
