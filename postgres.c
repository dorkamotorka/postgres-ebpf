//go:build ignore

#include "postgres.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Instead of allocating on bpf stack, we allocate on a per-CPU array map due to BPF stack limit
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

// Instead of allocating on bpf stack, we allocate on a per-CPU array map due to BPF stack limit of 512 bytes
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

// To transfer read parameters from enter to exit
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

// Map to share l7 events with the userspace application
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

// Processing enter of write syscall triggered on the client side
static __always_inline
int process_enter_of_syscalls_write(__u64 fd, char* buf, __u64 payload_size){
    
    // Retrieve the l7_request struct from the eBPF map (check above the map definition, why we use per-CPU array map for this purpose)
    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);
    if (!req) {
        return 0;
    }

    // Check if the L7 protocol is Postgres otherwise set to unknown
    req->protocol = PROTOCOL_UNKNOWN;
    req->request_type = 0;
    if (buf) {
        if (parse_client_postgres_data(buf, payload_size, &req->request_type)) {
            bpf_printk("Client request type: %c", req->request_type);
            req->protocol = PROTOCOL_POSTGRES;
        } else {
	    // Not recognizing client request as PostgreSQL protocol
	    return 0;
	}
    }

    // Copy the payload from the packet and check whether it fit below the MAX_PAYLOAD_SIZE
    bpf_probe_read(&req->payload, sizeof(req->payload), (const void *)buf);
    if (payload_size > MAX_PAYLOAD_SIZE) {
        // We werent able to copy all of it (setting payload_read_complete to 0)
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    } else {
        req->payload_size = payload_size;
        req->payload_read_complete = 1;
    }

    // correlate client→server writes with later server reads on the same socket
    struct socket_key k = {};
    __u64 id = bpf_get_current_pid_tgid();
    k.pid = id >> 32;
    k.fd = fd;
    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if (res < 0) {
        bpf_printk("Failed to store struct to active_l7_requests eBPF map");
    }

    return 0;
}

// Processing enter of read syscall triggered on the server side
static __always_inline
int process_enter_of_syscalls_read(__u64 fd, char* buf, __u64 payload_size) {
    __u64 id = bpf_get_current_pid_tgid();

    // Store an active read struct for later usage
    // Needed to pass fd, buf and count to sys_enter_exit
    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.size = payload_size;
    long res = bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    if (res < 0) {
        bpf_printk("write to active_reads failed");     
    }

    return 0;
}

static __always_inline
int process_exit_of_syscalls_read(void* ctx, __s64 ret) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    // Retrieve the active read struct from the enter of read syscall
    struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_info) {
        return 0;
    }

    // Retrieve the socket to which the client wrote
    // We can afford that since this eBPF program is meant for single-node environments
    // Where of our interest are only the clients on current node that write to the PostgreSQL (running on the same node)
    struct socket_key k = {};
    k.pid = pid;
    k.fd = read_info->fd;
    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!active_req) {
        return 0;
    }

    // Retrieve the active L7 event struct from the eBPF map (check above the map definition, why we use per-CPU array map for this purpose)
    // This event struct is then forwarded to the userspace application
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&active_l7_requests, &k);
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    e->fd = k.fd;
    e->pid = k.pid;
    e->protocol = active_req->protocol;
    e->payload_size = active_req->payload_size;
    e->payload_read_complete = active_req->payload_read_complete;
    e->request_type = active_req->request_type;
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

    // All data is now stored in the L7 Event and we can clean up the structs in the eBPF maps
    bpf_map_delete_elem(&active_reads, &id);
    bpf_map_delete_elem(&active_l7_requests, &k);

    // Forward L7 event to userspace application
    bpf_printk("Sending out event for request type %d", active_req->request_type);
    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        bpf_printk("Failed write to l7_events");     
    }

    bpf_printk("\n");

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter* ctx) {
    return process_enter_of_syscalls_write(ctx->args[0], (char *)ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter* ctx) {
    return process_enter_of_syscalls_read(ctx->args[0], (char *)ctx->args[1], ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit* ctx, int ret) {
    return process_exit_of_syscalls_read(ctx, ret);
}
