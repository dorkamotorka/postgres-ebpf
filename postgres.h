#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_PAYLOAD_SIZE 1024

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_POSTGRES	1

#define METHOD_UNKNOWN      0
#define METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE   1
#define METHOD_SIMPLE_QUERY 2
#define METHOD_EXTENDED_QUERY 3

#define COMMAND_COMPLETE 1
#define ERROR_RESPONSE 2

// Q(1 byte), length(4 bytes), query(length-4 bytes)
#define POSTGRES_MESSAGE_SIMPLE_QUERY 'Q' // 'Q' + 4 bytes of length + query

// C(1 byte), length(4 bytes), Byte1('S' to close a prepared statement; or 'P' to close a portal), name of the prepared statement or portal(length-5 bytes)
#define POSTGRES_MESSAGE_CLOSE 'C'

// X(1 byte), length(4 bytes)
#define POSTGRES_MESSAGE_TERMINATE 'X'

// C(1 byte), length(4 bytes), tag(length-4 bytes)
#define POSTGRES_MESSAGE_COMMAND_COMPLETION 'C'

// prepared statement
#define POSTGRES_MESSAGE_PARSE 'P' // 'P' + 4 bytes of length + query
#define POSTGRES_MESSAGE_BIND 'B' // 'P' + 4 bytes of length + query

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct socket_key {
    __u64 fd;
    __u32 pid;
    __u8 is_tls;
};

struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};

struct trace_event_raw_sys_enter_write {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_enter_read{
    struct trace_entry ent;
    int __syscall_nr;
    unsigned long int fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_exit_read {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 method;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
    __u32 seq;
    __u32 tid;
};

struct l7_event {
    __u64 fd;
    __u64 write_time_ns;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 failed;
    __u8 is_tls;
    __u32 seq;
    __u32 tid;
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

    // Connection termination has the Terminate identifier ("X") and the length is 4 bytes
    if (identifier == POSTGRES_MESSAGE_TERMINATE && bpf_htonl(len) == 4) {
        bpf_printk("Client will send Terminate packet\n");
        *request_type = identifier;
        return 1;
    }

    // Simple Query Protocol
    if (identifier == POSTGRES_MESSAGE_SIMPLE_QUERY) {
        *request_type = identifier;
        bpf_printk("Client will send a Simple Query\n");
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
            bpf_printk("Client will send an Extended Query\n");
            *request_type = identifier;
            return 1;
        }
    }

    return 0;
}

static __always_inline
__u32 parse_postgres_server_resp(char *buf, int buf_size) {
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

    // Identifies the message as an error.
    if (identifier == 'E') {
        return ERROR_RESPONSE;
    }

    // TODO: multiple pg messages can be in one packet, need to parse all of them and check if any of them is a command complete
    // assume C came if you see a T or D
    // when parsed C, it will have sql command in it (tag field, e.g. SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, etc.)
    if (identifier == 't' || identifier == 'T' || identifier == 'D' || identifier == 'C') {
        return COMMAND_COMPLETE;
    }

    return 0;
}