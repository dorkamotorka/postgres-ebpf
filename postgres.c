//go:build ignore

// After socket creation and connection establishment, the kernel will call the
// write function of the socket's protocol handler to send data to the remote
// peer. The kernel will call the read function of the socket's protocol handler
// to receive data from the remote peer.

// Flow:
// 1. sys_enter_write
// 2. sys_enter_read
// 3. sys_exit_read

#include "postgres.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

    bpf_probe_read(&req->payload, sizeof(req->payload), (const void *)buf);
    if (count > MAX_PAYLOAD_SIZE) {
        // will not be able to copy all of it
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    } else {
        req->payload_size = count;
        req->payload_read_complete = 1;
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