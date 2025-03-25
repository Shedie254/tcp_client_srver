#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define LOG_FILE "server.log"

void log_activity(FILE *log, const char *message) {
    time_t now = time(NULL);
    char timestamp[20];
    strftime(timestamp, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(log, "[%s] %s\n", timestamp, message);
    printf("[%s] %s\n", timestamp, message);
    fflush(log);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }

    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        perror("Failed to open log file");
        log = stdout;
    }

    int port = atoi(argv[1]);
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_activity(log, "Socket creation failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_activity(log, "Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 5) < 0) {
        log_activity(log, "Listen failed");
        exit(EXIT_FAILURE);
    }

    log_activity(log, "Server started and listening...");

    while (1) {
        // Accept connection
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            log_activity(log, "Accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &address.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(address.sin_port);
        
        char client_id[50];
        snprintf(client_id, sizeof(client_id), "%s:%d-%04d", client_ip, client_port, rand() % 10000);
        
        char log_msg[100];
        snprintf(log_msg, sizeof(log_msg), "Client %s connected", client_id);
        log_activity(log, log_msg);

        // File transfer loop
        while (1) {
            char buffer[BUFFER_SIZE] = {0};
            ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE);
            
            if (bytes_read <= 0) break; // Client disconnected or error
            
            // Log received content
            snprintf(log_msg, sizeof(log_msg), "Received from %s: %ld bytes", client_id, bytes_read);
            log_activity(log, log_msg);
            log_activity(log, "----- CONTENT START -----");
            log_activity(log, buffer);
            log_activity(log, "----- CONTENT END -----");
        }

        snprintf(log_msg, sizeof(log_msg), "Client %s disconnected", client_id);
        log_activity(log, log_msg);
        close(client_fd);
    }

    close(server_fd);
    fclose(log);
    return 0;
}