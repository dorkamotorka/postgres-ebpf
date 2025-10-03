package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf postgres postgres.c

import (
	"os"
	"log"
	"fmt"
	"unsafe"
	"strings"
	"regexp"
	"encoding/json"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

var re *regexp.Regexp
var keywords = []string{"SELECT", "INSERT INTO", "UPDATE", "DELETE FROM", "CREATE TABLE", "ALTER TABLE", "DROP TABLE", "TRUNCATE TABLE", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "CREATE INDEX", "DROP INDEX", "CREATE VIEW", "DROP VIEW", "GRANT", "REVOKE", "EXECUTE"}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	var pgObjs postgresObjects
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

	// Case-insensitive matching
	re = regexp.MustCompile(strings.Join(keywords, "|"))
	pgStatements := make(map[string]string)

	for {
		var record perf.Record
		err := L7EventsReader.ReadInto(&record)
		if err != nil {
			log.Print("error reading from perf array")
		}

		if record.LostSamples != 0 {
			log.Printf("lost samples l7-event %d", record.LostSamples)
		}

		if record.RawSample == nil || len(record.RawSample) == 0 {
			log.Print("read sample l7-event nil or empty")
			return
		}

		l7Event := (*postgresL7Event)(unsafe.Pointer(&record.RawSample[0]))

		protocol := L7ProtocolConversion(l7Event.Protocol).String()

		// copy payload slice
		payload := [1024]uint8{}
		copy(payload[:], l7Event.Payload[:])

		if (protocol == "POSTGRES") {
			out, err := parseSqlCommand(l7Event, &pgStatements)
			if (err != nil) {
				log.Printf("Error parsing sql command: %s", err)
			} else if (out != "") {
				event := struct {
				    Fd                  uint64 `json:"Fd"`
				    Pid                 uint32 `json:"Pid"`
				    Protocol            string `json:"Protocol"`
				    PayloadSize         uint32 `json:"PayloadSize"`
				    PayloadReadComplete uint8  `json:"PayloadReadComplete"`
				    RequestType         uint8  `json:"RequestType"`
				    Payload             string `json:"Payload"`
				}{
				    Fd:                  l7Event.Fd,
				    Pid:                 l7Event.Pid,
				    Protocol:            protocol,
				    PayloadSize:         l7Event.PayloadSize,
				    PayloadReadComplete: l7Event.PayloadReadComplete,
				    RequestType:         l7Event.RequestType,
				    Payload:             out,
				}

				b, _ := json.MarshalIndent(event, "", "  ")
				fmt.Printf("%s\n", b)
			}
		}
	}
}
