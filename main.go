package main

import (
	"log"
	"time"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go postgres postgres.c -- -I../headers

var pgObjs postgresObjects

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	pgObjs = postgresObjects{}
	if err := loadPostgresObjects(&pgObjs, nil); err != nil {
		log.Fatal(err)
	}

	l, err := link.Tracepoint("syscalls", "sys_enter_write", pgObjs.HandleWrite, nil)
	if err != nil {
		log.Fatal("link sys_enter_write tracepoint")
	}
	defer l.Close()

	for {
		time.Sleep(1 * time.Second)
	}
}