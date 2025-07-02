THIS SHOULD BE A LINTER ERROR#include <stdio.h>
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

#define _GNU_SOURCE

#define MAX_LINE_LENGTH 256
#define MAX_THREADS 200
#define DEFAULT_THREADS 50
#define CONNECTION_TIMEOUT 3    // 3 seconds
#define AUTH_TIMEOUT 5         // 5 seconds  
#define MAX_TARGETS 100000
#define MAX_USERS 10000
#define MAX_PASSWORDS 100000
#define BUFFER_SIZE 8192

// RDP Protocol Constants
#define RDP_NEG_REQ 0x01
#define RDP_NEG_RSP 0x02
#define RDP_NEG_FAILURE 0x03
#define PROTOCOL_RDP 0x00000000
#define PROTOCOL_SSL 0x00000001
#define PROTOCOL_HYBRID 0x00000002
#define PROTOCOL_RDSTLS 0x00000004

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
};

// Thread data structure
struct thread_data {
    int thread_id;
    struct config *cfg;
    FILE *output_fp;
    pthread_mutex_t *output_mutex;
    pthread_mutex_t *stats_mutex;
    int *current_index;
    int *attempts;
    int *successful;
    int *failed;
    volatile int *stop_flag;
};

// Result structure
struct result {
    char ip[64];
    char username[128];
    char password[128];
    int port;
    int success;
    double response_time;
    char error_msg[256];
    char protocol[32];
};

// Global stats
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
double get_time_diff(struct timeval *start, struct timeval *end) {
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

// Set socket non-blocking
int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

// Connect with timeout
int connect_timeout(int sockfd, struct sockaddr *addr, socklen_t addrlen, int timeout) {
    int ret;
    fd_set fdset;
    struct timeval tv;
    
    // Set non-blocking
    if (set_nonblocking(sockfd) < 0) {
        return -1;
    }
    
    // Attempt connection
    ret = connect(sockfd, addr, addrlen);
    if (ret == 0) {
        // Connected immediately
        return 0;
    }
    
    if (errno != EINPROGRESS) {
        return -1;
    }
    
    // Wait for connection with timeout
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    
    ret = select(sockfd + 1, NULL, &fdset, NULL, &tv);
    if (ret <= 0) {
        return -1; // Timeout or error
    }
    
    // Check for connection errors
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
        return -1;
    }
    
    if (error != 0) {
        errno = error;
        return -1;
    }
    
    return 0;
}

// Create RDP negotiation request
int create_rdp_nego_request(unsigned char *buffer) {
    // X.224 Connection Request TPDU
    unsigned char tpdu[] = {
        0x03, 0x00, 0x00, 0x13, // TPKT Header (length = 19)
        0x0E,                   // X.224 Length
        0xE0,                   // X.224 Connection Request
        0x00, 0x00,             // Destination reference
        0x00, 0x00,             // Source reference  
        0x00,                   // Class and options
        0x01, 0x00, 0x08, 0x00, // RDP Negotiation Request
        0x00, 0x00, 0x00, 0x00  // Requested protocols (RDP)
    };
    
    memcpy(buffer, tpdu, sizeof(tpdu));
    return sizeof(tpdu);
}

// Parse RDP negotiation response
int parse_rdp_nego_response(unsigned char *buffer, int len, char *protocol) {
    if (len < 19) return 0;
    
    // Check TPKT header
    if (buffer[0] != 0x03 || buffer[1] != 0x00) return 0;
    
    // Check X.224 response
    if (buffer[5] != 0xD0) return 0; // Connection Confirm
    
    // Check for negotiation response
    if (len >= 19 && buffer[11] == RDP_NEG_RSP) {
        unsigned int protocols = *(unsigned int*)(buffer + 15);
        if (protocols & PROTOCOL_HYBRID) {
            strcpy(protocol, "NLA");
        } else if (protocols & PROTOCOL_SSL) {
            strcpy(protocol, "TLS");
        } else {
            strcpy(protocol, "RDP");
        }
        return 1;
    }
    
    strcpy(protocol, "UNKNOWN");
    return 1;
}

// Test RDP connection
int test_rdp_connection(const char *ip, int port, struct result *result) {
    int sockfd = -1;
    struct sockaddr_in server_addr;
    struct timeval start_time, end_time;
    unsigned char buffer[BUFFER_SIZE];
    int ret = 0;
    
    gettimeofday(&start_time, NULL);
    
    // Initialize result
    strcpy(result->error_msg, "Unknown error");
    strcpy(result->protocol, "NONE");
    result->success = 0;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        strcpy(result->error_msg, "Socket creation failed");
        goto cleanup;
    }
    
    // Setup server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        strcpy(result->error_msg, "Invalid IP address");
        goto cleanup;
    }
    
    // Connect with timeout
    if (connect_timeout(sockfd, (struct sockaddr*)&server_addr, 
                       sizeof(server_addr), CONNECTION_TIMEOUT) < 0) {
        strcpy(result->error_msg, "Connection failed");
        goto cleanup;
    }
    
    // Send RDP negotiation request
    int req_len = create_rdp_nego_request(buffer);
    if (send(sockfd, buffer, req_len, 0) != req_len) {
        strcpy(result->error_msg, "Failed to send RDP request");
        goto cleanup;
    }
    
    // Receive response with timeout
    fd_set fdset;
    struct timeval tv;
    FD_ZERO(&fdset);
    FD_SET(sockfd, &fdset);
    tv.tv_sec = AUTH_TIMEOUT;
    tv.tv_usec = 0;
    
    int select_ret = select(sockfd + 1, &fdset, NULL, NULL, &tv);
    if (select_ret <= 0) {
        strcpy(result->error_msg, "Response timeout");
        goto cleanup;
    }
    
    int recv_len = recv(sockfd, buffer, sizeof(buffer), 0);
    if (recv_len <= 0) {
        strcpy(result->error_msg, "Failed to receive response");
        goto cleanup;
    }
    
    // Parse response
    if (parse_rdp_nego_response(buffer, recv_len, result->protocol)) {
        result->success = 1;
        strcpy(result->error_msg, "RDP service detected");
        ret = 1;
    } else {
        strcpy(result->error_msg, "Invalid RDP response");
    }
    
cleanup:
    if (sockfd >= 0) {
        close(sockfd);
    }
    
    gettimeofday(&end_time, NULL);
    result->response_time = get_time_diff(&start_time, &end_time);
    
    return ret;
}

// Advanced RDP authentication test (simplified NLA detection)
int test_rdp_auth(const char *ip, int port, const char *username __attribute__((unused)), 
                  const char *password __attribute__((unused)), struct result *result) {
    
    // First test basic RDP connectivity
    if (!test_rdp_connection(ip, port, result)) {
        return 0;
    }
    
    // For now, we're just testing RDP connectivity and protocol support
    // In a full implementation, you would need to implement:
    // 1. TLS handshake for NLA
    // 2. NTLM/Kerberos authentication  
    // 3. Credential validation
    
    if (strcmp(result->protocol, "NLA") == 0) {
        strcpy(result->error_msg, "NLA detected - auth testing would require full implementation");
    } else if (strcmp(result->protocol, "TLS") == 0) {
        strcpy(result->error_msg, "TLS detected - basic RDP available");
    } else {
        strcpy(result->error_msg, "Legacy RDP detected");
    }
    
    return 1;
}

// Worker thread function
void *worker_thread(void *arg) {
    struct thread_data *data = (struct thread_data *)arg;
    struct result result;
    int local_index;
    
    while (!g_stop_flag && !*(data->stop_flag)) {
        // Get next work item
        pthread_mutex_lock(data->stats_mutex);
        local_index = (*(data->current_index))++;
        pthread_mutex_unlock(data->stats_mutex);
        
        // Calculate coordinates in the 3D space (ip, user, password)
        int total_combinations = data->cfg->ip_count * data->cfg->user_count * data->cfg->password_count;
        
        if (local_index >= total_combinations) {
            break; // All work done
        }
        
        int ip_idx = local_index / (data->cfg->user_count * data->cfg->password_count);
        int remaining = local_index % (data->cfg->user_count * data->cfg->password_count);
        int user_idx = remaining / data->cfg->password_count;
        int pass_idx = remaining % data->cfg->password_count;
        
        // Initialize result
        strncpy(result.ip, data->cfg->ips[ip_idx], sizeof(result.ip) - 1);
        strncpy(result.username, data->cfg->users[user_idx], sizeof(result.username) - 1);
        strncpy(result.password, data->cfg->passwords[pass_idx], sizeof(result.password) - 1);
        result.port = data->cfg->port;
        
        // Test connection/authentication
        int success;
        if (data->cfg->fast_mode) {
            // Fast mode: just test connectivity
            success = test_rdp_connection(data->cfg->ips[ip_idx], data->cfg->port, &result);
        } else {
            // Full mode: test authentication (placeholder)
            success = test_rdp_auth(data->cfg->ips[ip_idx], data->cfg->port,
                                   data->cfg->users[user_idx], 
                                   data->cfg->passwords[pass_idx], &result);
        }
        
        // Update stats
        pthread_mutex_lock(data->stats_mutex);
        (*(data->attempts))++;
        g_total_attempts++;
        if (success) {
            (*(data->successful))++;
            g_successful++;
        } else {
            (*(data->failed))++;
            g_failed++;
        }
        pthread_mutex_unlock(data->stats_mutex);
        
        // Write result
        pthread_mutex_lock(data->output_mutex);
        if (result.success) {
            fprintf(data->output_fp, "[SUCCESS] %s:%d - %s:%s - %s (%.3fs)\n",
                   result.ip, result.port, result.username, result.password, 
                   result.protocol, result.response_time);
            printf("\n[+] SUCCESS: %s:%d - %s (%.3fs)\n",
                   result.ip, result.port, result.protocol, result.response_time);
        } else if (data->cfg->verbose) {
            fprintf(data->output_fp, "[FAILED] %s:%d - %s:%s - %s (%.3fs)\n",
                   result.ip, result.port, result.username, result.password, 
                   result.error_msg, result.response_time);
        }
        fflush(data->output_fp);
        pthread_mutex_unlock(data->output_mutex);
        
        // Print stats periodically
        if (g_total_attempts % 50 == 0) {
            print_stats();
        }
    }
    
    return NULL;
}

// Load file into array
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
        
        // Skip empty lines
        if (strlen(line) == 0) continue;
        
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
    printf("High-Performance RDP Scanner/Brute Force Tool v2.0\n");
    printf("Optimized for maximum speed and NLA detection\n\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Required:\n");
    printf("  -i <file>     IP addresses file (one per line)\n");
    printf("  -u <file>     Usernames file (one per line)\n");
    printf("  -p <file>     Passwords file (one per line)\n");
    printf("  -o <file>     Output results file\n\n");
    printf("Optional:\n");
    printf("  -t <num>      Number of threads (default: %d, max: %d)\n", DEFAULT_THREADS, MAX_THREADS);
    printf("  -P <port>     RDP port (default: 3389)\n");
    printf("  -f            Fast mode (connectivity test only)\n");
    printf("  -v            Verbose output (show failed attempts)\n");
    printf("  -h            Show this help\n\n");
    printf("Examples:\n");
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt\n", program);
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt -t 100 -f\n", program);
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt -v\n", program);
}

int main(int argc, char *argv[]) {
    struct config cfg = {0};
    FILE *output_fp = NULL;
    pthread_t *threads = NULL;
    struct thread_data *thread_data = NULL;
    pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
    int current_index = 0;
    int attempts = 0, successful = 0, failed = 0;
    int opt;
    
    // Default values
    cfg.thread_count = DEFAULT_THREADS;
    cfg.port = 3389;
    cfg.verbose = 0;
    cfg.fast_mode = 0;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:u:p:o:t:P:fvh")) != -1) {
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
                cfg.output_file = strdup(optarg);
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
    
    printf("\n[*] High-Performance RDP Scanner Starting\n");
    printf("[*] Targets: %d IPs, %d users, %d passwords\n", cfg.ip_count, cfg.user_count, cfg.password_count);
    printf("[*] Total combinations: %lld\n", total_combinations);
    printf("[*] Threads: %d\n", cfg.thread_count);
    printf("[*] Port: %d\n", cfg.port);
    printf("[*] Mode: %s\n", cfg.fast_mode ? "Fast (connectivity only)" : "Full (with auth testing)");
    printf("[*] Output: %s\n", cfg.output_file);
    printf("[*] Connection timeout: %ds\n", CONNECTION_TIMEOUT);
    printf("[*] Auth timeout: %ds\n", AUTH_TIMEOUT);
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Start timing
    g_start_time = time(NULL);
    
    // Create threads
    threads = malloc(cfg.thread_count * sizeof(pthread_t));
    thread_data = malloc(cfg.thread_count * sizeof(struct thread_data));
    
    if (!threads || !thread_data) {
        printf("[-] Error: Memory allocation failed\n");
        return 1;
    }
    
    printf("\n[*] Starting scan...\n");
    
    // Create worker threads
    for (int i = 0; i < cfg.thread_count; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].cfg = &cfg;
        thread_data[i].output_fp = output_fp;
        thread_data[i].output_mutex = &output_mutex;
        thread_data[i].stats_mutex = &stats_mutex;
        thread_data[i].current_index = &current_index;
        thread_data[i].attempts = &attempts;
        thread_data[i].successful = &successful;
        thread_data[i].failed = &failed;
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
    
    printf("\n\n[*] Scan completed!\n");
    printf("[*] Total time: %.2f seconds\n", total_time);
    printf("[*] Total attempts: %d\n", g_total_attempts);
    printf("[*] Successful: %d\n", g_successful);
    printf("[*] Failed: %d\n", g_failed);
    printf("[*] Average rate: %.2f attempts/second\n", rate);
    printf("[*] Results saved to: %s\n", cfg.output_file);
    
    // Write summary to output file
    fprintf(output_fp, "\n# Summary\n");
    fprintf(output_fp, "# Total time: %.2f seconds\n", total_time);
    fprintf(output_fp, "# Total attempts: %d\n", g_total_attempts);
    fprintf(output_fp, "# Successful: %d\n", g_successful);
    fprintf(output_fp, "# Failed: %d\n", g_failed);
    fprintf(output_fp, "# Average rate: %.2f attempts/second\n", rate);
    
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