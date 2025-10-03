#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_PAYLOAD_SIZE 1024

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_POSTGRES   1

// Q(1 byte), length(4 bytes), query(length-4 bytes)
#define POSTGRES_MESSAGE_SIMPLE_QUERY 'Q' // 'Q' + 4 bytes of length + query

// prepared statement
#define POSTGRES_MESSAGE_PARSE 'P' // 'P' + 4 bytes of length + query
#define POSTGRES_MESSAGE_BIND  'B' // 'P' + 4 bytes of length + query

struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
};

struct socket_key {
    __u64 fd;
    __u32 pid;
};

struct l7_request {
    __u8 protocol;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
};

struct l7_event {
    __u64 fd;
    __u32 pid;
    __u8 protocol;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
};

// Used on the client side
// Checks if the message is a postgresql Q, C, X message
static __always_inline
int parse_client_postgres_data(char *buf, int buf_size, __u8 *request_type) {
    // Return immeadiately if buffer is empty
    if (buf_size < 1) {
        return 0;
    }

    // Parse the first byte of the buffer
    // This is the identifier of the PostgresQL message
    char identifier;
    if (bpf_probe_read(&identifier, sizeof(identifier), (void *)((char *)buf)) < 0) {
        return 0;
    }

    // the next four bytes specify the length of the rest of the message
    __u32 len;
    if (bpf_probe_read(&len, sizeof(len), (void *)((char *)buf + 1)) < 0) {
        return 0;
    }

    // Simple Query
    if (identifier == POSTGRES_MESSAGE_SIMPLE_QUERY) {
        *request_type = identifier;
        bpf_printk("Client send a Simple Query");
        return 1;
    }

    // Extended Query Protocol (Prepared Statement) 
    // > P/D/S (Parse/Describe/Sync) creating a prepared statement
    // > B/E/S (Bind/Execute/Sync) executing a prepared statement
    if (identifier == POSTGRES_MESSAGE_PARSE || identifier == POSTGRES_MESSAGE_BIND) {
        // Read last 5 bytes of the buffer (Sync message)
        char sync[5];
        if (bpf_probe_read(&sync, sizeof(sync), (void *)((char *)buf + (buf_size - 5))) < 0) {
            return 0;
        }

        // Extended query protocol messages often end with a Sync (S) message.
        // Sync message is a 5 byte message with the first byte being 'S' and the rest indicating the length of the message, including self (4 bytes in this case - so no message body)
        if (sync[0] == 'S' && sync[1] == 0 && sync[2] == 0 && sync[3] == 0 && sync[4] == 4) {
            bpf_printk("Client send an Extended Query");
            *request_type = identifier;
            return 1;
        }
    }

    return 0;
}
