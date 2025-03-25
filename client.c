#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>

#define BUFFER_SIZE 1024
#define PROGRESS_BAR_WIDTH 50

void print_progress(double percentage) {
    int val = (int)(percentage * 100);
    int lpad = (int)(percentage * PROGRESS_BAR_WIDTH);
    int rpad = PROGRESS_BAR_WIDTH - lpad;
    printf("\r[%3d%%] [%.*s%*s]", val, lpad, "||||||||||||||||||||||||||||||||||||||||||||||||||", rpad, "");
    fflush(stdout);
}

void log_client(const char *message) {
    time_t now;
    time(&now);
    char timestr[20];
    strftime(timestr, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
    printf("[%s] %s\n", timestr, message);
}

void error(const char *msg) {
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_IP> <port> <file1> [file2] ...\n", argv[0]);
        exit(1);
    }

    char *server_ip = argv[1];
    int port = atoi(argv[2]);
    int sockfd;
    struct sockaddr_in serv_addr;

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        error("ERROR opening socket");
    }

    // Initialize server address structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        error("ERROR invalid server IP");
    }

    // Connect to server
    log_client("Connecting to server...");
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        error("ERROR connecting to server");
    }
    log_client("Connected to server");

    // Process each file
    for (int i = 3; i < argc; i++) {
        char *filename = argv[i];
        log_client("Preparing to send file...");
        
        // Get file size
        struct stat st;
        if (stat(filename, &st) < 0) {
            printf("Error getting file size for %s\n", filename);
            continue;
        }
        long file_size = st.st_size;
        
        FILE *file = fopen(filename, "r");
        if (file == NULL) {
            printf("Error opening file %s\n", filename);
            continue;
        }

        printf("Sending file: %s (Size: %ld bytes)\n", filename, file_size);
        
        char buffer[BUFFER_SIZE];
        size_t bytes_read;
        long total_sent = 0;
        
        // Send file in chunks with progress
        while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            int n = write(sockfd, buffer, bytes_read);
            if (n < 0) {
                error("ERROR writing to socket");
            }
            total_sent += n;
            
            // Update progress
            double progress = (double)total_sent / file_size;
            print_progress(progress);
        }
        
        printf("\n");
        fclose(file);
        log_client("File sent successfully");
    }

    close(sockfd);
    log_client("Disconnected from server");
    return 0;
}