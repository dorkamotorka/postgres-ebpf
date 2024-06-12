# PostgresQL eBPF

- Run eBPF program using `sudo ./postgres`
- Inspect eBPF program logs using `sudo cat /sys/kernel/debug/tracing/trace_pipe`
- Run the PostgresQL Container using `docker run --name postgres-container -e POSTGRES_PASSWORD=mysecretpassword -d -p 5432:5432 postgres`
- Run client inside `/test` using `go run client.go`