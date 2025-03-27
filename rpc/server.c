#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>
#include <time.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define AUTH_TOKEN "SECRET_RPC_KEY"
#define HEARTBEAT_INTERVAL 30
#define MAX_CLIENTS 100

typedef struct {
    char command[32];
    char data[BUFFER_SIZE];
} RPCRequest;

typedef struct {
    int status;
    char result[BUFFER_SIZE];
} RPCResponse;

typedef struct {
    int socket;
    SSL *ssl;
    time_t last_activity;
} ClientInfo;

ClientInfo *clients[MAX_CLIENTS] = {NULL};
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
SSL_CTX *ssl_ctx;

void log_activity(const char *message) {
    time_t now = time(NULL);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    FILE *log_file = fopen("server.log", "a");
    if (log_file) {
        fprintf(log_file, "[%s] %s\n", time_buf, message);
        fclose(log_file);
    }
    printf("[%s] %s\n", time_buf, message);
}

void cleanup_client(int index) {
    pthread_mutex_lock(&mutex);
    if (index >= 0 && index < MAX_CLIENTS && clients[index]) {
        if (clients[index]->ssl) {
            SSL_shutdown(clients[index]->ssl);
            SSL_free(clients[index]->ssl);
        }
        if (clients[index]->socket >= 0) {
            close(clients[index]->socket);
        }
        free(clients[index]);
        clients[index] = NULL;
    }
    pthread_mutex_unlock(&mutex);
}

SSL_CTX *initialize_ssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}

int authenticate(SSL *ssl) {
    char auth_token[BUFFER_SIZE];
    int bytes = SSL_read(ssl, auth_token, BUFFER_SIZE - 1);
    if (bytes <= 0) {
        ERR_print_errors_fp(stderr);
        log_activity("Authentication failed - read error");
        return 0;
    }
    auth_token[bytes] = '\0';

    if (strcmp(auth_token, AUTH_TOKEN) != 0) {
        log_activity("Authentication failed - invalid token");
        return 0;
    }

    if (SSL_write(ssl, "AUTH_SUCCESS", 12) <= 0) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    return 1;
}

void process_rpc_request(RPCRequest *req, RPCResponse *res) {
    if (strcmp(req->command, "REVERSE") == 0) {
        int len = strlen(req->data);
        for (int i = 0; i < len; i++) {
            res->result[i] = req->data[len - i - 1];
        }
        res->result[len] = '\0';
        res->status = 0;
    } 
    else if (strcmp(req->command, "UPPERCASE") == 0) {
        for (int i = 0; req->data[i]; i++) {
            res->result[i] = toupper((unsigned char)req->data[i]);
        }
        res->result[strlen(req->data)] = '\0';
        res->status = 0;
    } 
    else {
        strcpy(res->result, "Unknown command");
        res->status = -1;
    }
}

void *client_handler(void *arg) {
    int client_index = *(int *)arg;
    ClientInfo *client = clients[client_index];
    SSL *ssl = client->ssl;
    char client_ip[INET_ADDRSTRLEN];
    
    // Get client IP
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client->socket, (struct sockaddr*)&client_addr, &addr_len);
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    
    char log_msg[BUFFER_SIZE];
    snprintf(log_msg, sizeof(log_msg), "Client connected from %s", client_ip);
    log_activity(log_msg);

    if (!authenticate(ssl)) {
        cleanup_client(client_index);
        free(arg);
        return NULL;
    }

    while (1) {
        RPCRequest req;
        RPCResponse res;
        memset(&req, 0, sizeof(req));
        memset(&res, 0, sizeof(res));

        // Receive complete request
        int total_received = 0;
        while (total_received < sizeof(req)) {
            int bytes = SSL_read(ssl, (char*)&req + total_received, 
                               sizeof(req) - total_received);
            if (bytes <= 0) {
                snprintf(log_msg, sizeof(log_msg), "Client %s disconnected", client_ip);
                log_activity(log_msg);
                goto cleanup;
            }
            total_received += bytes;
        }

        snprintf(log_msg, sizeof(log_msg), "Request from %s: %s '%s'", 
                client_ip, req.command, req.data);
        log_activity(log_msg);

        if (strcmp(req.command, "EXIT") == 0) {
            snprintf(log_msg, sizeof(log_msg), "Client %s exited", client_ip);
            log_activity(log_msg);
            break;
        }

        process_rpc_request(&req, &res);

        if (SSL_write(ssl, &res, sizeof(res)) <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
    }

cleanup:
    cleanup_client(client_index);
    free(arg);
    return NULL;
}

int main() {
    ssl_ctx = initialize_ssl();
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT)
    };

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log_activity("Server started");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, client_sock);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        pthread_mutex_lock(&mutex);
        int client_index = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] == NULL) {
                clients[i] = malloc(sizeof(ClientInfo));
                clients[i]->socket = client_sock;
                clients[i]->ssl = ssl;
                clients[i]->last_activity = time(NULL);
                client_index = i;
                break;
            }
        }
        pthread_mutex_unlock(&mutex);

        if (client_index == -1) {
            log_activity("Max clients reached - connection refused");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_sock);
            continue;
        }

        int *thread_arg = malloc(sizeof(int));
        *thread_arg = client_index;

        pthread_t thread;
        if (pthread_create(&thread, NULL, client_handler, thread_arg)) {
            perror("Thread creation failed");
            cleanup_client(client_index);
            free(thread_arg);
        } else {
            pthread_detach(thread);
        }
    }

    close(server_fd);
    SSL_CTX_free(ssl_ctx);
    return 0;
}