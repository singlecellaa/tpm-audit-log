#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <limits.h>

#include "cli.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (1024 * (EVENT_SIZE + 16))
#define LOG_FILE "data/audit_log.txt"
#define PATH_MAX 256
#define MAX_WATCHED_FILES 100

// Error handling macro
#define CHECK_ERROR(condition, msg, action) \
    if (condition) { \
        fprintf(stderr, "Error: %s: %s\n", msg, strerror(errno)); \
        action; \
    }

// Function to convert binary to hex string
void Bin2HexStr(const unsigned char *bin, size_t len, char *hex_out, size_t hex_len) {
    static const char *hex_chars = "0123456789abcdef";
    if (!bin || !hex_out || hex_len < len * 2 + 1) return;
    for (size_t i = 0; i < len; ++i) {
        hex_out[i * 2] = hex_chars[(bin[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex_chars[bin[i] & 0xF];
    }
    hex_out[len * 2] = '\0';
}

// Watched file structure
typedef struct {
    int wd;
    char path[PATH_MAX];
} watched_file_t;

// Global variables
int inotify_fd;
watched_file_t watched_files[MAX_WATCHED_FILES];
int num_watched_files = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int running = 1;

// 函数声明
void log_audit_event(const char *event_type, const char *file_path, const char *user, int success);
const char *get_current_user();
void cleanup();
void *monitor_thread(void *arg);
void *command_thread(void *arg);
int add_watch(const char *path);
int remove_watch(const char *path);
void list_watched_files();
const char *get_path_from_wd(int wd);

void log_audit_event(const char *event_type, const char *file_path, const char *user, int success) {
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    char log_entry[1024];
    snprintf(log_entry, sizeof(log_entry), "%s | %s | %s | %s | %s",
             timestamp, user, event_type, file_path, success ? "SUCCESS" : "FAILURE");

    // Compute SHA256 of log_entry
    unsigned char hash[HASH_SIZE];
    SHA256((const unsigned char *)log_entry, strlen(log_entry), hash);

    // Sign the hash with TPM
    struct TpmSigner signer;
    if (tpm_signer_init(&signer, NULL, DEFAULT_PERSISTENT_KEY) != 0) {
        fprintf(stderr, "TPM signer init failed\n");
        // Fallback to unsigned log
        FILE *log_fp = fopen(LOG_FILE, "a");
        if (log_fp) {
            fputs(log_entry, log_fp);
            fputs(" | UNSIGNED\n", log_fp);
            fclose(log_fp);
        }
        return;
    }

    unsigned char *sig = NULL;
    size_t sig_len = 0;
    if (tpm_signer_sign(&signer, hash, &sig, &sig_len) != 0) {
        fprintf(stderr, "TPM sign failed\n");
        tpm_signer_cleanup(&signer);
        // Fallback
        FILE *log_fp = fopen(LOG_FILE, "a");
        if (log_fp) {
            fputs(log_entry, log_fp);
            fputs(" | UNSIGNED\n", log_fp);
            fclose(log_fp);
        }
        return;
    }

    // Hex encode signature
    char sig_hex[1024]; // Assume sig_len <= 256
    Bin2HexStr(sig, sig_len, sig_hex, sizeof(sig_hex));

    // Write log_entry | sig_hex to file
    FILE *log_fp = fopen(LOG_FILE, "a");
    if (log_fp) {
        fputs(log_entry, log_fp);
        fputs(" | ", log_fp);
        fputs(sig_hex, log_fp);
        fputs("\n", log_fp);
        fclose(log_fp);
        printf("Logged: %s\n", log_entry);
    } else {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
    }

    free(sig);
    tpm_signer_cleanup(&signer);
}

const char *get_current_user() {
    uid_t uid = geteuid();  // 使用有效用户ID
    struct passwd *pw = getpwuid(uid);
    if (!pw) {
        return "unknown";
    }
    return pw->pw_name;
}

void cleanup() {
    printf("Cleaning up...\n");
    running = 0;
   
}

// Get path from watch descriptor
const char *get_path_from_wd(int wd) {
    pthread_mutex_lock(&mutex);
    for (int i = 0; i < num_watched_files; i++) {
        if (watched_files[i].wd == wd) {
            pthread_mutex_unlock(&mutex);
            return watched_files[i].path;
        }
    }
    pthread_mutex_unlock(&mutex);
    return "unknown";
}

// Add a file to watch
int add_watch(const char *path) {
    pthread_mutex_lock(&mutex);
    
    // Check if already watching
    for (int i = 0; i < num_watched_files; i++) {
        if (strcmp(watched_files[i].path, path) == 0) {
            printf("Already watching: %s\n", path);
            pthread_mutex_unlock(&mutex);
            return -1;
        }
    }
    
    // Check if we have space
    if (num_watched_files >= MAX_WATCHED_FILES) {
        printf("Maximum number of watched files reached\n");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    
    // Check if file exists
    if (!file_exists(path)) {
        printf("File does not exist: %s\n", path);
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    
    // Add watch
    int wd = inotify_add_watch(inotify_fd, path, 
                              IN_ACCESS | IN_MODIFY | IN_ATTRIB | IN_CLOSE_WRITE | 
                              IN_CLOSE_NOWRITE | IN_OPEN | IN_MOVED_FROM | 
                              IN_MOVED_TO | IN_CREATE | IN_DELETE);
    
    if (wd < 0) {
        perror("inotify_add_watch");
        pthread_mutex_unlock(&mutex);
        return -1;
    }
    
    // Add to list
    watched_files[num_watched_files].wd = wd;
    strcpy(watched_files[num_watched_files].path, path);
    num_watched_files++;
    
    printf("Added watch for: %s (wd=%d)\n", path, wd);
    pthread_mutex_unlock(&mutex);
    return 0;
}

// Remove a file from watch
int remove_watch(const char *path) {
    pthread_mutex_lock(&mutex);
    
    for (int i = 0; i < num_watched_files; i++) {
        if (strcmp(watched_files[i].path, path) == 0) {
            inotify_rm_watch(inotify_fd, watched_files[i].wd);
            
            // Remove from list
            for (int j = i; j < num_watched_files - 1; j++) {
                watched_files[j] = watched_files[j + 1];
            }
            num_watched_files--;
            
            printf("Removed watch for: %s\n", path);
            pthread_mutex_unlock(&mutex);
            return 0;
        }
    }
    
    printf("File not being watched: %s\n", path);
    pthread_mutex_unlock(&mutex);
    return -1;
}

// List watched files
void list_watched_files() {
    pthread_mutex_lock(&mutex);
    printf("Currently watched files:\n");
    for (int i = 0; i < num_watched_files; i++) {
        printf("  %s (wd=%d)\n", watched_files[i].path, watched_files[i].wd);
    }
    if (num_watched_files == 0) {
        printf("  None\n");
    }
    pthread_mutex_unlock(&mutex);
}

// Monitor thread function
void *monitor_thread(void *arg) {
    char buffer[BUF_LEN];
    ssize_t length;
    
    printf("Monitor thread started\n");
    
    while (running) {
        length = read(inotify_fd, buffer, BUF_LEN);
        if (length < 0) {
            if (running) {
                perror("read from inotify");
            }
            break;
        }
        
        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            
            if (event->mask) {
                const char *user = get_current_user();
                const char *event_type = "UNKNOWN";
                int success = 1;
                const char *file_path = get_path_from_wd(event->wd);
                
                // Determine event type
                if (event->mask & IN_ACCESS) {
                    event_type = "ACCESS";
                } else if (event->mask & IN_MODIFY) {
                    event_type = "MODIFY";
                } else if (event->mask & IN_ATTRIB) {
                    event_type = "ATTRIB";
                } else if (event->mask & IN_CLOSE_WRITE) {
                    event_type = "CLOSE_WRITE";
                } else if (event->mask & IN_CLOSE_NOWRITE) {
                    event_type = "CLOSE_NOWRITE";
                } else if (event->mask & IN_OPEN) {
                    event_type = "OPEN";
                } else if (event->mask & IN_CREATE) {
                    event_type = "CREATE";
                } else if (event->mask & IN_DELETE) {
                    event_type = "DELETE";
                    success = 0;
                } else if (event->mask & IN_MOVED_FROM) {
                    event_type = "MOVED_FROM";
                } else if (event->mask & IN_MOVED_TO) {
                    event_type = "MOVED_TO";
                }
                
                log_audit_event(event_type, file_path, user, success);
                
                // Extra output to console
                printf("Detected: %s on %s by %s\n", event_type, file_path, user);
            }
            
            i += EVENT_SIZE + event->len;
        }
    }
    
    printf("Monitor thread stopped\n");
    return NULL;
}

// Command thread function
void *command_thread(void *arg) {
    char command[256];
    
    printf("Command thread started\n");
    printf("Available commands:\n");
    printf("  add <path>    - Add file to watch\n");
    printf("  remove <path> - Remove file from watch\n");
    printf("  list          - List watched files\n");
    printf("  append <text> - Append text to log chain\n");
    printf("  append-file <path> - Append file contents to log chain\n");
    printf("  verify        - Verify log chain integrity\n");
    printf("  verify-sig <pubkey> - Verify signature with public key\n");
    printf("  head          - Show current chain head\n");
    printf("  nv-read-head  - Read head from TPM NV\n");
    printf("  quit          - Exit program\n\n");
    
    while (running) {
        printf("> ");
        fflush(stdout);
        
        if (fgets(command, sizeof(command), stdin) == NULL) {
            break;
        }
        
        // Remove newline
        command[strcspn(command, "\n")] = 0;
        
        if (strncmp(command, "add ", 4) == 0) {
            const char *path = command + 4;
            add_watch(path);
        } else if (strncmp(command, "remove ", 7) == 0) {
            const char *path = command + 7;
            remove_watch(path);
        } else if (strcmp(command, "list") == 0) {
            list_watched_files();
        } else if (strncmp(command, "append ", 7) == 0) {
            const char *text = command + 7;
            do_append(text);
        } else if (strncmp(command, "append-file ", 12) == 0) {
            const char *path = command + 12;
            FILE *f = fopen(path, "r");
            if (!f) { 
                fprintf(stderr, "Cannot open %s\n", path); 
            } else {
                char buf[MAX_LOG_LINE];
                int rc_total = 0;
                while (fgets(buf, sizeof(buf), f)) {
                    size_t len = strlen(buf);
                    if (len && (buf[len-1] == '\n' || buf[len-1] == '\r')) buf[len-1] = '\0';
                    if (do_append(buf) != 0) rc_total = 1;
                }
                fclose(f);
                if (rc_total == 0) {
                    printf("Appended file %s\n", path);
                }
            }
        } else if (strcmp(command, "verify") == 0) {
            do_verify();
        } else if (strncmp(command, "verify-sig ", 11) == 0) {
            const char *pub = command + 11;
            do_verify_sig(pub);
        } else if (strcmp(command, "head") == 0) {
            do_head();
        } else if (strcmp(command, "nv-read-head") == 0) {
            do_nv_read_head();
        } else if (strcmp(command, "quit") == 0) {
            running = 0;
            break;
        } else if (strlen(command) > 0) {
            printf("Unknown command: %s\n", command);
        }
    }
    
    printf("Command thread stopped\n");
    return NULL;
}

int main(int argc, char *argv[]) {
    //cli_run(argc, argv);

    pthread_t monitor_tid, command_tid;
    
    // Initialize inotify
    inotify_fd = inotify_init();
    CHECK_ERROR(inotify_fd < 0, "inotify_init", return 1);
    
    printf("TPM Audit Logger started\n");
    printf("Log file: %s\n\n", LOG_FILE);
    
    // Start threads
    if (pthread_create(&monitor_tid, NULL, monitor_thread, NULL) != 0) {
        perror("pthread_create monitor");
        close(inotify_fd);
        return 1;
    }
    
    if (pthread_create(&command_tid, NULL, command_thread, NULL) != 0) {
        perror("pthread_create command");
        running = 0;
        pthread_join(monitor_tid, NULL);
        close(inotify_fd);
        return 1;
    }
    
    // Wait for command thread to finish
    pthread_join(command_tid, NULL);
    
    // Stop monitor thread
    running = 0;
    
    // Close inotify to wake up monitor thread
    close(inotify_fd);
    
    // Wait for monitor thread
    pthread_join(monitor_tid, NULL);
    
    // Cleanup
    cleanup();
    
    return 0;
}