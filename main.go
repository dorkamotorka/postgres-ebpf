package main

import (
	"os"
	"regexp"
	"strings"
	"log"
	"fmt"
	"unsafe"
	"bytes"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

var re *regexp.Regexp
var keywords = []string{"SELECT", "INSERT INTO", "UPDATE", "DELETE FROM", "CREATE TABLE", "ALTER TABLE", "DROP TABLE", "TRUNCATE TABLE", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "CREATE INDEX", "DROP INDEX", "CREATE VIEW", "DROP VIEW", "GRANT", "REVOKE", "EXECUTE"}

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

func getKey(pid uint32, fd uint64, stmtName string) string {
	return fmt.Sprintf("%d-%d-%s", pid, fd, stmtName)
}

// Check if a string contains SQL keywords
func containsSQLKeywords(input string) bool {
	return re.MatchString(strings.ToUpper(input))
}

func parseSqlCommand(d *bpfL7Event, pgStatements *map[string]string) (string, error) {
	r := d.Payload[:d.PayloadSize]
	var sqlCommand string
	if PostgresMethodConversion(d.Method).String() == SIMPLE_QUERY {
		// Q, 4 bytes of length, sql command

		// skip Q, (simple query)
		r = r[1:]

		// skip 4 bytes of length
		r = r[4:]

		// get sql command
		sqlCommand = string(r)

		// garbage data can come for postgres, we need to filter out
		// search statement for sql keywords like
		if !containsSQLKeywords(sqlCommand) {
			return "", fmt.Errorf("no sql command found")
		}
	} else if PostgresMethodConversion(d.Method).String() == EXTENDED_QUERY { // prepared statement
		// Parse or Bind message
		id := r[0]
		switch id {
		case 'P':
			// 1 byte P
			// 4 bytes len
			// prepared statement name(str) (null terminated)
			// query(str) (null terminated)
			// parameters
			var stmtName string
			var query string
			vars := bytes.Split(r[5:], []byte{0})
			if len(vars) >= 3 {
				stmtName = string(vars[0])
				query = string(vars[1])
			} else if len(vars) == 2 { // query too long for our buffer
				stmtName = string(vars[0])
				query = string(vars[1]) + "..."
			} else {
				return "", fmt.Errorf("could not parse 'parse' frame for postgres")
			}
			
			(*pgStatements)[getKey(d.Pid, d.Fd, stmtName)] = query
			return fmt.Sprintf("PREPARE %s AS %s", stmtName, query), nil
		case 'B':
			// 1 byte B
			// 4 bytes len
			// portal str (null terminated)
			// prepared statement name str (null terminated)
			// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-BIND

			var stmtName string
			vars := bytes.Split(r[5:], []byte{0})
			if len(vars) >= 2 {
				stmtName = string(vars[1])
			} else {
				return "", fmt.Errorf("could not parse bind frame for postgres")
			}

			query, ok := (*pgStatements)[getKey(d.Pid, d.Fd, stmtName)]
			if !ok || query == "" { // we don't have the query for the prepared statement
				// Execute (name of prepared statement) [(parameter)]
				return fmt.Sprintf("EXECUTE %s *values*", stmtName), nil
			}
			return query, nil
		default:
			return "", fmt.Errorf("could not parse extended query for postgres")
		}
	} else if PostgresMethodConversion(d.Method).String() == CLOSE_OR_TERMINATE {
		sqlCommand = string(r)
	}

	return sqlCommand, nil
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
/* func uint8ToBool(num uint8) bool {
	return num != 0
} */

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

		// TODO: investigate why this is happening
		if record.RawSample == nil || len(record.RawSample) == 0 {
			log.Print("read sample l7-event nil or empty")
			return
		}

		l7Event := (*bpfL7Event)(unsafe.Pointer(&record.RawSample[0]))

		protocol := L7ProtocolConversion(l7Event.Protocol).String()
/* 		var method string
		switch protocol {
		case L7_PROTOCOL_POSTGRES:
			method = PostgresMethodConversion(l7Event.Method).String()
		default:
			method = "Unknown"
		} */

		// copy payload slice
		payload := [1024]uint8{}
		copy(payload[:], l7Event.Payload[:])

		if (protocol == "POSTGRES") {
			out, err := parseSqlCommand(l7Event, &pgStatements)
			if err != nil {
				log.Printf("Error parsing sql command: %s", err)
			} else {
				log.Printf("%s", out)
			}
		}
	}
}