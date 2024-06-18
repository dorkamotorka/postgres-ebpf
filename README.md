# PostgresQL eBPF

This is a demo code, for showcasing Observability of the PostgreSQL protocol using eBPF. This code is inspired by Alaz, Kubernetes eBPF agent, developed by Anteon.

<img width="1481" alt="postgres" src="https://github.com/dorkamotorka/postgres-ebpf/assets/48418580/58cc493e-654c-4d56-badf-6f0ccb29b328">

In order to try it out locally:

- Run eBPF program using
  ```
  go generate
  go build
  sudo ./postgres
  ```
- Run the PostgresQL Container using
  ```
  docker run --name postgres-container -e POSTGRES_PASSWORD=mysecretpassword -d -p 5432:5432 postgres
  ```
- Run client inside `/test` using 
  ```
  go run client.go
  ```
- In another shell, inspect eBPF program logs using
  ```
  sudo cat /sys/kernel/debug/tracing/trace_pipe
  ```
- To run performance evaluation, inside `/perf` directory run:
  ```
  go run measure.go
  ```