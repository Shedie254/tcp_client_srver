#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define BUFFER_SIZE 1024
#define MAX_CLIENTS 5
#define LOG_FILE "server.log"

void log_message(FILE *log_file, const char *message) {
    time_t now;
    time(&now);
    char timestr[20];
    strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(log_file, "[%s] %s\n", timestr, message);
    printf("[%s] %s\n", timestr, message);
}

void error(const char *msg, FILE *log_file) {
    log_message(log_file, msg);
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    FILE *log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        perror("Failed to open log file");
        log_file = stdout;
    }

    int port = atoi(argv[1]);
    int sockfd, newsockfd;
    struct sockaddr_in serv_addr, cli_addr;
    socklen_t clilen;
    char buffer[BUFFER_SIZE];

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket", log_file);
    }

    // Initialize server address structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);

    // Bind socket to port
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        error("ERROR on binding", log_file);
    }

    // Listen for incoming connections
    listen(sockfd, MAX_CLIENTS);
    log_message(log_file, "Server started and listening for connections...");

    while (1) {
        // Accept a new connection
        clilen = sizeof(cli_addr);
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) {
            error("ERROR on accept", log_file);
        }

        char client_info[100];
        snprintf(client_info, sizeof(client_info), 
                "New client connected: %s:%d", 
                inet_ntoa(cli_addr.sin_addr), 
                ntohs(cli_addr.sin_port));
        log_message(log_file, client_info);

        // Read message from client
        memset(buffer, 0, BUFFER_SIZE);
        int n = read(newsockfd, buffer, BUFFER_SIZE - 1);
        if (n < 0) {
            error("ERROR reading from socket", log_file);
        }

        char msg_log[BUFFER_SIZE + 100];
        snprintf(msg_log, sizeof(msg_log), 
                "Received from %s:%d: %s", 
                inet_ntoa(cli_addr.sin_addr), 
                ntohs(cli_addr.sin_port),
                buffer);
        log_message(log_file, msg_log);

        // Close client connection
        close(newsockfd);
        snprintf(client_info, sizeof(client_info),
                "Client %s:%d disconnected",
                inet_ntoa(cli_addr.sin_addr),
                ntohs(cli_addr.sin_port));
        log_message(log_file, client_info);
    }

    close(sockfd);
    fclose(log_file);
    return 0;
}