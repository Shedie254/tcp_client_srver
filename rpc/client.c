#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <ctype.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024
#define AUTH_TOKEN "SECRET_RPC_KEY"
#define AUTH_TOKEN "SECRET_RPC_KEY"  // Must match client's token

typedef struct {
    char command[32];
    char data[BUFFER_SIZE];
} RPCRequest;

typedef struct {
    int status;
    char result[BUFFER_SIZE];
} RPCResponse;

void initialize_ssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}

SSL *connect_to_server(SSL_CTX *ctx) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Certificate verification failed\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connected to RPC server securely.\n");
    return ssl;
}

void communicate_with_server(SSL *ssl) {
    RPCRequest req;
    RPCResponse res;
    char buffer[BUFFER_SIZE];

    // 1. Send authentication token
    printf("Sending authentication token...\n");
    if (SSL_write(ssl, AUTH_TOKEN, strlen(AUTH_TOKEN)) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to send authentication token\n");
        return;
    }

    // 2. Receive authentication response
    printf("Waiting for server response...\n");
    int auth_bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (auth_bytes <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to receive authentication response\n");
        return;
    }
    buffer[auth_bytes] = '\0';

    // 3. Validate server response
    if (strcmp(buffer, "AUTH_SUCCESS") != 0) {
        fprintf(stderr, "Authentication rejected. Server response: '%s'\n", buffer);
        return;
    }

    printf("Successfully authenticated with server\n");

    // Main communication loop
    while (1) {
        memset(&req, 0, sizeof(req));
        memset(&res, 0, sizeof(res));

        // Get user input
        printf("\nAvailable Commands:\n");
        printf("1. REVERSE - Reverse a string\n");
        printf("2. UPPERCASE - Convert to uppercase\n");
        printf("3. ADMIN - Admin commands\n");
        printf("4. EXIT - Close connection\n");
        printf("Enter choice: ");

        int choice;
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Invalid input\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        getchar(); // Consume newline

        if (choice == 4) {
            printf("Exiting...\n");
            SSL_write(ssl, "EXIT", 4);
            break;
        }

        // Prepare request
        switch (choice) {
            case 1:
                strcpy(req.command, "REVERSE");
                printf("Enter string to reverse: ");
                break;
            case 2:
                strcpy(req.command, "UPPERCASE");
                printf("Enter string to uppercase: ");
                break;
            case 3:
                strcpy(req.command, "ADMIN");
                printf("Enter admin command: ");
                break;
            default:
                printf("Invalid choice\n");
                continue;
        }

        // Get data input
        fgets(req.data, BUFFER_SIZE, stdin);
        req.data[strcspn(req.data, "\n")] = '\0';

        // Send request
        if (SSL_write(ssl, &req, sizeof(req)) <= 0) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "Failed to send request\n");
            break;
        }

        // Receive response
        int total_received = 0;
        while (total_received < sizeof(res)) {
            int bytes = SSL_read(ssl, (char*)&res + total_received, 
                               sizeof(res) - total_received);
            if (bytes <= 0) {
                ERR_print_errors_fp(stderr);
                fprintf(stderr, "Connection lost\n");
                goto disconnect;
            }
            total_received += bytes;
        }

        // Process response
        if (res.status == 0) {
            printf("Server response: %s\n", res.result);
        } else {
            printf("Error: %s\n", res.result);
        }
        continue;

    disconnect:
        break;
    }
}

int main() {
    initialize_ssl();
    SSL_CTX *ctx = create_ssl_context();
    SSL *ssl = connect_to_server(ctx);

    communicate_with_server(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}