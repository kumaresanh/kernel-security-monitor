// Package sensor provides eBPF event types and ring buffer parsing for the Kernel Security Monitor sensor.
package sensor

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// EventType mirrors the enum in sensor.c
type EventType uint32

const (
	EventExecve  EventType = 1
	EventOpenat  EventType = 2
	EventConnect EventType = 3
)

func (t EventType) String() string {
	switch t {
	case EventExecve:
		return "execve"
	case EventOpenat:
		return "openat"
	case EventConnect:
		return "connect"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

const (
	MaxPayload  = 256
	TaskCommLen = 16
)

// RawEvent is the wire format from BPF ring buffer — must match struct event in sensor.c exactly.
type RawEvent struct {
	EventType   uint32
	PID         uint32
	PPID        uint32
	UID         uint32
	TimestampNs uint64
	Comm        [TaskCommLen]byte
	Payload     [MaxPayload]byte
	RetVal      int32
	PayloadLen  uint32
	DstPort     uint16
	DstIP4      uint32
	SAFamily    uint16
	Flags       int32
}

// RawEventSize is the expected size of the BPF event struct
var RawEventSize = int(unsafe.Sizeof(RawEvent{}))

// Event is the parsed, user-friendly version of RawEvent.
type Event struct {
	Type        EventType `json:"type"`
	TypeStr     string    `json:"type_str"`
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	UID         uint32    `json:"uid"`
	TimestampNs uint64    `json:"timestamp_ns"`
	Comm        string    `json:"comm"`
	Payload     string    `json:"payload"`
	RetVal      int32     `json:"ret_val,omitempty"`
	// Connect-specific
	DstPort  uint16 `json:"dst_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SAFamily uint16 `json:"sa_family,omitempty"`
	// Openat-specific
	Flags    int32  `json:"flags,omitempty"`
	IsWrite  bool   `json:"is_write,omitempty"`
}

// ParseEvent converts a raw BPF event into a parsed Event.
func ParseEvent(raw *RawEvent) Event {
	e := Event{
		Type:        EventType(raw.EventType),
		TypeStr:     EventType(raw.EventType).String(),
		PID:         raw.PID,
		PPID:        raw.PPID,
		UID:         raw.UID,
		TimestampNs: raw.TimestampNs,
		Comm:        nullTermStr(raw.Comm[:]),
		Payload:     nullTermStr(raw.Payload[:]),
		RetVal:      raw.RetVal,
		SAFamily:    raw.SAFamily,
		DstPort:     raw.DstPort,
		Flags:       raw.Flags,
	}

	// Parse IP address for connect events
	if e.Type == EventConnect && raw.DstIP4 != 0 {
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, raw.DstIP4)
		e.DstIP = ip.String()
	}

	// Determine if openat is a write
	if e.Type == EventOpenat {
		// O_WRONLY=1, O_RDWR=2, O_CREAT=0x40, O_TRUNC=0x200
		e.IsWrite = (raw.Flags&0x1 != 0) || (raw.Flags&0x2 != 0) || (raw.Flags&0x40 != 0)
	}

	return e
}

// nullTermStr extracts a null-terminated string from a byte slice.
func nullTermStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// KillEvent mirrors the BPF-LSM kill_event struct.
type KillEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	TimestampNs uint64
	Comm        [16]byte
	Filename    [256]byte
}
