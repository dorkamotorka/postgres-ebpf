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

struct read_enter_args {
    __u64 id;
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 time;
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
    
    __u32 seq; // tcp sequence number
    __u32 tid;
};

// Instead of allocating on bpf stack, we allocate on a per-CPU array map
// In other works - in order to avoid 
// "error: Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map"
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct socket_key);
    __type(value, struct l7_request);
} active_l7_requests SEC(".maps");

// send l7 events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

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
        bpf_printk("Client will send Terminate packet\n");
        *request_type = identifier;
        return 1;
    }

    // long queries can be split into multiple packets
    // therefore specified length can exceed the buf_size 
    // normally (len + 1 byte of identifier  == buf_size) should be true

    // Simple Query Protocol
    if (identifier == POSTGRES_MESSAGE_SIMPLE_QUERY) {
        *request_type = identifier;
        bpf_printk("Client will send a Simple Query\n");
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
            bpf_printk("Client will send an extended query (Parse/Bind)\n");
            *request_type = identifier;
            return 1;
        }
    }

    return 0;
}

static __always_inline
__u32 parse_postgres_server_resp(char *buf, int buf_size) {
    char identifier;
    int len;
    if (bpf_probe_read(&identifier, sizeof(identifier), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (bpf_probe_read(&len, sizeof(len), (void *)((char *)buf+1)) < 0) {
        return 0;
    }
    len = bpf_htonl(len);

    if (len+1 > buf_size) {
        return 0;
    }

    // TODO: write a state machine to parse the response
    
    // '1' : ParseComplete
    // '2' : BindComplete
    // '3' : CloseComplete
    // 'T' : RowDescription
    // 'D' : DataRow
    // 'C' : CommandComplete
    // 'E' : ErrorResponse
    // 'I' : EmptyQueryResponse
    // 'N' : NoData
    // 'S' : PortalSuspended
    // 's' : ParameterStatus
    // 'K' : BackendKeyData
    // 'Z' : ReadyForQuery



    // if ((cmd == '1' || cmd == '2') && length == 4 && buf_size >= 10) {
    //     if (bpf_probe_read(&cmd, sizeof(cmd), (void *)((char *)buf+5)) < 0) {
    //         return 0;
    //     }
    //     if (bpf_probe_read(&length, sizeof(length), (void *)((char *)buf+5+1)) < 0) {
    //         return 0;
    //     }
    // }

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

// Processing enter of write syscall
static __always_inline
int process_enter_of_syscalls_write(void* ctx, __u64 fd, __u8 is_tls, char* buf, __u64 count){
    __u64 timestamp = bpf_ktime_get_ns();
    __u64 id = bpf_get_current_pid_tgid();

    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }

    req->protocol = PROTOCOL_UNKNOWN;
    req->method = METHOD_UNKNOWN;
    req->request_type = 0;
    req->write_time_ns = timestamp;

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = fd;
    k.is_tls = is_tls;

    if (buf) {
        if (parse_client_postgres_data(buf, count, &req->request_type)) {
            bpf_printk("Client request type: %c\n", req->request_type);
            if (req->request_type == POSTGRES_MESSAGE_TERMINATE){
                req->protocol = PROTOCOL_POSTGRES;
                req->method = METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE;
            }
            req->protocol = PROTOCOL_POSTGRES;
        }
    }

    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if (res < 0) {
        bpf_printk("write failed to active_l7_requests");
    }

    return 0;
}

// Processing enter of read syscalls
static __always_inline
int process_enter_of_syscalls_read(void *ctx, struct read_enter_args *params) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    struct read_args args = {};
    args.fd = params->fd;
    args.buf = params->buf;
    args.size = params->size;
    args.read_start_ns = params->time;

    long res = bpf_map_update_elem(&active_reads, &(params->id), &args, BPF_ANY);
    if (res < 0) {
        bpf_printk("write to active_reads failed");     
    }

    return 0;
}

static __always_inline
int process_exit_of_syscalls_read(void* ctx, __u64 id, __u32 pid, __s64 ret, __u8 is_tls) {
    __u64 timestamp = bpf_ktime_get_ns();
    struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_info) {
        return 0;
    }

    struct socket_key k = {};
    k.pid = pid;
    k.fd = read_info->fd; 
    k.is_tls = is_tls;

    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!active_req) {
        return 0;
    }

    // Instead of allocating on bpf stack, use cpu map
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&active_l7_requests, &k);
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    e->is_tls = is_tls;
    e->fd = k.fd;
    e->pid = k.pid;

    e->method = active_req->method;

    e->protocol = active_req->protocol;
    e->duration = timestamp - active_req->write_time_ns;
    
    e->write_time_ns = active_req->write_time_ns;
    
    // request payload
    e->payload_size = active_req->payload_size;
    e->payload_read_complete = active_req->payload_read_complete;
    
    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

    e->failed = 0; // success

    // for distributed tracing
    e->seq = active_req->seq;
    e->tid = active_req->tid;

    e->status = 0;

    if (read_info->buf) {
        if (e->protocol == PROTOCOL_POSTGRES){
            e->status = parse_postgres_server_resp(read_info->buf, ret);
            if (active_req->request_type == POSTGRES_MESSAGE_SIMPLE_QUERY) {
                e->method = METHOD_SIMPLE_QUERY;
                bpf_printk("Simple Query read on the Server\n");
            } else if (active_req->request_type == POSTGRES_MESSAGE_PARSE || active_req->request_type == POSTGRES_MESSAGE_BIND) {
                e->method = METHOD_EXTENDED_QUERY;
                bpf_printk("Extended Query read on the Server\n");
            }
        }
    } else {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    bpf_map_delete_elem(&active_reads, &id);
    bpf_map_delete_elem(&active_l7_requests, &k);

    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        bpf_printk("failed write to l7_events");     
    }

    return 0;
}


// TODO: how is this custom struct passed to the bpf program?
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter_write* ctx)
{
    return process_enter_of_syscalls_write(ctx, ctx->fd, 0, ctx->buf, ctx->count);
}

// TODO: how is this custom struct passed to the bpf program?
SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter_read* ctx) {
    __u64 time =  bpf_ktime_get_ns();
    __u64 id = bpf_get_current_pid_tgid();
    struct read_enter_args params = {
        .id = id,
        .fd = ctx->fd,
        .buf = ctx->buf,
        .size = ctx->count,
        .time = time
    };

    return process_enter_of_syscalls_read(ctx, &params);
}

// TODO: how is this custom struct passed to the bpf program?
SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit_read* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return process_exit_of_syscalls_read(ctx, pid_tgid, pid, ctx->ret, 0);
}
