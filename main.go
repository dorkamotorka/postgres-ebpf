package main

import (
	"os"
	"log"
	"unsafe"
	"time"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	BPF_L7_PROTOCOL_UNKNOWN = iota
	BPF_L7_PROTOCOL_POSTGRES
)

// for user space
const (
	L7_PROTOCOL_POSTGRES = "POSTGRES"
	L7_PROTOCOL_UNKNOWN  = "UNKNOWN"
)

// match with values in l7_req.c, order is important
const (
	BPF_POSTGRES_METHOD_UNKNOWN = iota
	BPF_POSTGRES_METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE
	BPF_POSTGRES_METHOD_SIMPLE_QUERY
	BPF_POSTGRES_METHOD_EXTENDED_QUERY // for prepared statements

	// BPF_POSTGRES_METHOD_QUERY
	// BPF_POSTGRES_METHOD_EXECUTE
	// BPF_POSTGRES_METHOD_PARSE
	// BPF_POSTGRES_METHOD_BIND
	// BPF_POSTGRES_METHOD_DESCRIBE
	// BPF_POSTGRES_METHOD_SYNC
	// BPF_POSTGRES_METHOD_FLUSH
	// BPF_POSTGRES_METHOD_CONSUME
	// BPF_POSTGRES_METHOD_PARSE_COMPLETE
	// BPF_POSTGRES_METHOD_BIND_COMPLETE
	// BPF_POSTGRES_METHOD_CLOSE_COMPLETE
	// BPF_POSTGRES_METHOD_SYNC_COMPLETE
	// BPF_POSTGRES_METHOD_READY_FOR_QUERY
	//...
)

// for postgres, user space
const (
	CLOSE_OR_TERMINATE = "CLOSE_OR_TERMINATE"
	SIMPLE_QUERY       = "SIMPLE_QUERY"
	EXTENDED_QUERY     = "EXTENDED_QUERY"
)

type L7ProtocolConversion uint32
// String representation of the enumeration values
func (e L7ProtocolConversion) String() string {
	switch e {
	case BPF_L7_PROTOCOL_POSTGRES:
		return L7_PROTOCOL_POSTGRES
	case BPF_L7_PROTOCOL_UNKNOWN:
		return L7_PROTOCOL_UNKNOWN
	default:
		return "Unknown"
	}
}

// Custom type for the enumeration
type PostgresMethodConversion uint32

// String representation of the enumeration values
func (e PostgresMethodConversion) String() string {
	switch e {
	case BPF_POSTGRES_METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE:
		return CLOSE_OR_TERMINATE
	case BPF_POSTGRES_METHOD_SIMPLE_QUERY:
		return SIMPLE_QUERY
	case BPF_POSTGRES_METHOD_EXTENDED_QUERY:
		return EXTENDED_QUERY
	default:
		return "Unknown"
	}
}

// 0 is false, 1 is true
func uint8ToBool(num uint8) bool {
	return num != 0
}

type L7Event struct {
	Fd                  uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            string // L7_PROTOCOL_HTTP
	Tls                 bool   // Whether request was encrypted
	Method              string
	Payload             [1024]uint8
	PayloadSize         uint32 // How much of the payload was copied
	PayloadReadComplete bool   // Whether the payload was copied completely
	Failed              bool   // Request failed
	WriteTimeNs         uint64 // start time of write syscall
	Tid                 uint32
	Seq                 uint32 // tcp seq num
	EventReadTime       int64
}

type bpfL7Event struct {
	Fd                  uint64
	WriteTimeNs         uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	Payload             [1024]uint8
	PayloadSize         uint32
	PayloadReadComplete uint8
	Failed              uint8
	IsTls               uint8
	_                   [1]byte
	Seq                 uint32
	Tid                 uint32
	_                   [4]byte
}

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

	w, err := link.Tracepoint("syscalls", "sys_enter_write", pgObjs.HandleWrite, nil)
	if err != nil {
		log.Fatal("link sys_enter_write tracepoint")
	}
	defer w.Close()

	r, err := link.Tracepoint("syscalls", "sys_enter_read", pgObjs.HandleRead, nil)
	if err != nil {
		log.Fatal("link sys_enter_read tracepoint")
	}
	defer r.Close()

	rexit, err := link.Tracepoint("syscalls", "sys_exit_read", pgObjs.HandleReadExit, nil)
	if err != nil {
		log.Fatal("link sys_exit_read tracepoint")
	}
	defer rexit.Close()

	L7EventsReader, err := perf.NewReader(pgObjs.L7Events, int(4096)*os.Getpagesize())
	if err != nil {
		log.Fatal("error creating perf event array reader")
	}


	for {
		var record perf.Record
		err := L7EventsReader.ReadInto(&record)
		if err != nil {
			log.Print("error reading from perf array")
		}

		if record.LostSamples != 0 {
			log.Printf("lost samples l7-event %d", record.LostSamples)
		}

		// TODO: investigate why this is happening
		if record.RawSample == nil || len(record.RawSample) == 0 {
			log.Print("read sample l7-event nil or empty")
			return
		}

		l7Event := (*bpfL7Event)(unsafe.Pointer(&record.RawSample[0]))

		protocol := L7ProtocolConversion(l7Event.Protocol).String()
		var method string
		switch protocol {
		case L7_PROTOCOL_POSTGRES:
			method = PostgresMethodConversion(l7Event.Method).String()
		default:
			method = "Unknown"
		}

		// copy payload slice
		payload := [1024]uint8{}
		copy(payload[:], l7Event.Payload[:])

		if (protocol == "POSTGRES") {
			log.Printf("%d", l7Event.Fd)
			log.Printf("%d", l7Event.Pid)
			log.Printf("%d", l7Event.Status)
			log.Printf("%d", l7Event.Duration)
			log.Printf("%s", protocol)
			log.Printf("%t", uint8ToBool(l7Event.IsTls))
			log.Printf("%s", method)
			log.Printf("%s", payload)
			log.Printf("%d", l7Event.PayloadSize)
			log.Printf("%t", uint8ToBool(l7Event.PayloadReadComplete))
			log.Printf("%t", uint8ToBool(l7Event.Failed))
			log.Printf("%d", l7Event.WriteTimeNs)
			log.Printf("%d", l7Event.Tid)
			log.Printf("%d", l7Event.Seq)
			log.Printf("%d", time.Now().UnixMilli())
			log.Print("--------------------------------------------------")
		}
	}
}