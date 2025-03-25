#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>

#define CHUNK_SIZE 4096
#define PROGRESS_WIDTH 50

void print_progress(double percentage) {
    int val = (int)(percentage * 100);
    int pos = (int)(percentage * PROGRESS_WIDTH);
    printf("\r[%3d%%] [", val);
    for (int i = 0; i < PROGRESS_WIDTH; i++) {
        if (i < pos) printf("=");
        else printf(" ");
    }
    printf("]");
    fflush(stdout);
}

int send_file(int sock, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("File open failed");
        return -1;
    }

    // Get file size
    struct stat st;
    stat(filename, &st);
    long file_size = st.st_size;
    
    printf("Sending %s (%ld bytes)\n", filename, file_size);
    
    char buffer[CHUNK_SIZE];
    size_t bytes_read;
    long total_sent = 0;
    
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        if (send(sock, buffer, bytes_read, 0) < 0) {
            perror("Send failed");
            fclose(file);
            return -1;
        }
        total_sent += bytes_read;
        print_progress((double)total_sent / file_size);
    }
    
    printf("\n");
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <server_ip> <port> <file1> [file2...]\n", argv[0]);
        exit(1);
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(1);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    
    // Convert IP address
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(1);
    }

    // Connect to server
    printf("Connecting to server...\n");
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(1);
    }
    printf("Connected to server\n");

    // Send each file
    for (int i = 3; i < argc; i++) {
        printf("\nPreparing to send: %s\n", argv[i]);
        if (send_file(sock, argv[i]) == 0) {
            printf("Successfully sent: %s\n", argv[i]);
        } else {
            printf("Failed to send: %s\n", argv[i]);
        }
    }

    close(sock);
    printf("\nAll files transferred. Connection closed.\n");
    return 0;
}