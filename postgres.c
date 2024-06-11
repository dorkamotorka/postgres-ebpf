//go:build ignore

// After socket creation and connection establishment, the kernel will call the
// write function of the socket's protocol handler to send data to the remote
// peer. The kernel will call the read function of the socket's protocol handler
// to receive data from the remote peer.

// Flow:
// 1. sys_enter_write
    // -- TODO: check if write was successful (return value), sys_exit_write ?
// 2. sys_enter_read
// 3. sys_exit_read

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

struct trace_event_raw_sys_enter_write {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    char * buf;
    __u64 count;
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

// should used on client side
// checks if the message is a postgresql Q, C, X message
static __always_inline
int parse_client_postgres_data(char *buf, int buf_size, __u8 *request_type) {
    if (buf_size < 1) {
        return 0;
    }
    char identifier;
    __u32 len;
    if (bpf_probe_read(&identifier, sizeof(identifier), (void *)((char *)buf)) < 0) {
        return 0;
    }

    if (bpf_probe_read(&len, sizeof(len), (void *)((char *)buf+1)) < 0) {
        return 0;
    }
    len = bpf_htonl(len);

    if (identifier == POSTGRES_MESSAGE_TERMINATE && len == 4) {
        *request_type = identifier;
        return 1;
    }

    // long queries can be split into multiple packets
    // therefore specified length can exceed the buf_size 
    // normally (len + 1 byte of identifier  == buf_size) should be true

    // Simple Query Protocol
    if (identifier == POSTGRES_MESSAGE_SIMPLE_QUERY) {
        *request_type = identifier;
        return 1;
    }

    // Extended Query Protocol (Prepared Statement)
    // >P/D/S (Parse/Describe/Sync) creating a prepared statement
    // >B/E/S (Bind/Execute/Sync) executing a prepared statement
    if (identifier == POSTGRES_MESSAGE_PARSE || identifier == POSTGRES_MESSAGE_BIND) {
        // For fine grained parsing check Sync message, Http2 has a similar message starting with 'P' (PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n)
        // read last 5 bytes of the buffer
        char sync[5];
        if (bpf_probe_read(&sync, sizeof(sync), (void *)((char *)buf+buf_size-5)) < 0) {
            return 0;
        }
        if (sync[0] == 'S' && sync[1] == 0 && sync[2] == 0 && sync[3] == 0 && sync[4] == 4) {
            *request_type = identifier;
            return 1;
        }
    }

    return 0;
}

// Processing enter of write syscall
static __always_inline
int process_enter_of_syscalls_write(void* ctx, __u64 fd, __u8 is_tls, char* buf, __u64 count){
    __u64 timestamp = bpf_ktime_get_ns();

    struct l7_request req;
    req.protocol = PROTOCOL_UNKNOWN;
    req.method = METHOD_UNKNOWN;
    req.request_type = 0;
    req.write_time_ns = timestamp;

    if (buf) {
        parse_client_postgres_data(buf, count, &req.request_type);
    }

    if (req.request_type != 0) {
        bpf_printk("request_type: %d\n", req.request_type);
    }
    
    return 0;
}

// TODO: where does this custom struct comes from?
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter_write* ctx)
{
    return process_enter_of_syscalls_write(ctx, ctx->fd, 0, ctx->buf, ctx->count);
}