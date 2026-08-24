// Package sensor provides eBPF program loading and ring buffer management via cilium/ebpf.
package sensor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Loader manages eBPF program lifecycle.
type Loader struct {
	sensorSpec    *ebpf.CollectionSpec
	lsmSpec       *ebpf.CollectionSpec
	sensorColl    *ebpf.Collection
	lsmColl       *ebpf.Collection
	links         []link.Link
	ringReader    *ringbuf.Reader
	lsmRingReader *ringbuf.Reader
	denyMap       *ebpf.Map
	lsmAvailable  bool
	fallbackKill  bool
	logger        *slog.Logger
}

// Config controls loader behavior.
type Config struct {
	SensorObjPath    string
	LSMObjPath       string
	FallbackSignalKill bool
}

// NewLoader creates a new eBPF loader.
func NewLoader(cfg Config, logger *slog.Logger) *Loader {
	return &Loader{
		fallbackKill: cfg.FallbackSignalKill,
		logger:       logger,
	}
}

// Load loads and attaches eBPF programs.
func (l *Loader) Load(cfg Config) error {
	// Remove memlock limit for BPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load sensor programs
	sensorSpec, err := ebpf.LoadCollectionSpec(cfg.SensorObjPath)
	if err != nil {
		return fmt.Errorf("loading sensor spec: %w", err)
	}
	l.sensorSpec = sensorSpec

	sensorColl, err := ebpf.NewCollection(sensorSpec)
	if err != nil {
		return fmt.Errorf("creating sensor collection: %w", err)
	}
	l.sensorColl = sensorColl

	// Attach tracepoints
	tracepoints := map[string]string{
		"tracepoint_execve":  "syscalls/sys_enter_execve",
		"tracepoint_openat":  "syscalls/sys_enter_openat",
		"tracepoint_connect": "syscalls/sys_enter_connect",
	}
	for progName, tp := range tracepoints {
		prog, ok := sensorColl.Programs[progName]
		if !ok {
			return fmt.Errorf("program %s not found in sensor collection", progName)
		}
		// Parse group/name from "group/name"
		parts := splitTP(tp)
		lnk, err := link.Tracepoint(parts[0], parts[1], prog, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint %s: %w", tp, err)
		}
		l.links = append(l.links, lnk)
		l.logger.Info("attached tracepoint", "name", tp)
	}

	// Open ring buffer reader
	eventsMap, ok := sensorColl.Maps["events"]
	if !ok {
		return fmt.Errorf("events ring buffer map not found")
	}
	l.ringReader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}

	// Try loading LSM programs
	if err := l.loadLSM(cfg); err != nil {
		l.logger.Warn("BPF-LSM not available, using signal-kill fallback", "error", err)
		l.lsmAvailable = false
	} else {
		l.lsmAvailable = true
		l.logger.Info("BPF-LSM loaded and attached")
	}

	return nil
}

func (l *Loader) loadLSM(cfg Config) error {
	lsmSpec, err := ebpf.LoadCollectionSpec(cfg.LSMObjPath)
	if err != nil {
		return fmt.Errorf("loading LSM spec: %w", err)
	}
	l.lsmSpec = lsmSpec

	lsmColl, err := ebpf.NewCollection(lsmSpec)
	if err != nil {
		return fmt.Errorf("creating LSM collection: %w", err)
	}
	l.lsmColl = lsmColl

	// Attach the LSM program
	prog, ok := lsmColl.Programs["ksm_bprm_check"]
	if !ok {
		return fmt.Errorf("LSM program not found")
	}
	lsmLink, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return fmt.Errorf("attaching LSM: %w", err)
	}
	l.links = append(l.links, lsmLink)

	// Get deny map reference
	denyMap, ok := lsmColl.Maps["deny_exec_map"]
	if !ok {
		return fmt.Errorf("deny_exec_map not found")
	}
	l.denyMap = denyMap

	// Open LSM kill events ring buffer
	killEventsMap, ok := lsmColl.Maps["kill_events"]
	if ok {
		l.lsmRingReader, err = ringbuf.NewReader(killEventsMap)
		if err != nil {
			l.logger.Warn("could not create LSM kill events reader", "error", err)
		}
	}

	return nil
}

// ReadEvents reads parsed events from the ring buffer. Blocks until ctx is cancelled.
func (l *Loader) ReadEvents(ctx context.Context, out chan<- Event) error {
	l.logger.Info("starting ring buffer reader")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		record, err := l.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			l.logger.Error("reading ring buffer", "error", err)
			continue
		}

		if len(record.RawSample) < RawEventSize {
			l.logger.Warn("short event record", "size", len(record.RawSample), "expected", RawEventSize)
			continue
		}

		var raw RawEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			l.logger.Error("parsing event", "error", err)
			continue
		}

		event := ParseEvent(&raw)
		select {
		case out <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// DenyExec adds a PID to the BPF-LSM deny map, or falls back to SIGKILL.
func (l *Loader) DenyExec(pid uint32) error {
	if l.lsmAvailable && l.denyMap != nil && !l.fallbackKill {
		val := uint8(1)
		if err := l.denyMap.Put(pid, val); err != nil {
			l.logger.Error("failed to add PID to deny map, falling back to SIGKILL", "pid", pid, "error", err)
			return l.signalKill(pid)
		}
		l.logger.Info("PID added to BPF-LSM deny map", "pid", pid)
		return nil
	}
	return l.signalKill(pid)
}

func (l *Loader) signalKill(pid uint32) error {
	l.logger.Warn("sending SIGKILL (fallback)", "pid", pid)
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("finding process %d: %w", pid, err)
	}
	if err := proc.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("sending SIGKILL to %d: %w", pid, err)
	}
	return nil
}

// LSMAvailable reports whether BPF-LSM was successfully loaded.
func (l *Loader) LSMAvailable() bool {
	return l.lsmAvailable
}

// Close releases all eBPF resources.
func (l *Loader) Close() {
	if l.ringReader != nil {
		l.ringReader.Close()
	}
	if l.lsmRingReader != nil {
		l.lsmRingReader.Close()
	}
	for _, lnk := range l.links {
		lnk.Close()
	}
	if l.sensorColl != nil {
		l.sensorColl.Close()
	}
	if l.lsmColl != nil {
		l.lsmColl.Close()
	}
}

func splitTP(tp string) [2]string {
	for i, c := range tp {
		if c == '/' {
			return [2]string{tp[:i], tp[i+1:]}
		}
	}
	return [2]string{tp, ""}
}
