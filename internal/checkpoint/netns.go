package checkpoint

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sync"
	"time"
)

// ConnectionAttempt records an outbound connection captured by the sinkhole.
type ConnectionAttempt struct {
	Timestamp time.Time `json:"timestamp"`
	DstAddr   string    `json:"dst_addr"`
	DstPort   int       `json:"dst_port"`
	Family    int       `json:"family"`
	RawData   []byte    `json:"raw_data,omitempty"`
}

// Sinkhole creates an isolated network namespace and captures all outbound connections.
type Sinkhole struct {
	nsName      string
	port        int
	logger      *slog.Logger
	mu          sync.Mutex
	connections []ConnectionAttempt
	listener    net.Listener
}

// NewSinkhole creates an isolated network namespace with sinkhole routing.
func NewSinkhole(nsName string, port int, logger *slog.Logger) (*Sinkhole, error) {
	s := &Sinkhole{
		nsName: nsName,
		port:   port,
		logger: logger,
	}

	if err := s.createNamespace(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Sinkhole) createNamespace() error {
	// Create network namespace
	if err := runCmd("ip", "netns", "add", s.nsName); err != nil {
		return fmt.Errorf("creating netns %s: %w", s.nsName, err)
	}

	// Create veth pair
	vethHost := "veth-ksm-h"
	vethNS := "veth-ksm-n"

	cmds := [][]string{
		{"ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethNS},
		{"ip", "link", "set", vethNS, "netns", s.nsName},
		// Configure host side
		{"ip", "addr", "add", "10.200.0.1/24", "dev", vethHost},
		{"ip", "link", "set", vethHost, "up"},
		// Configure namespace side
		{"ip", "netns", "exec", s.nsName, "ip", "addr", "add", "10.200.0.2/24", "dev", vethNS},
		{"ip", "netns", "exec", s.nsName, "ip", "link", "set", vethNS, "up"},
		{"ip", "netns", "exec", s.nsName, "ip", "link", "set", "lo", "up"},
		// Route ALL traffic from namespace to sinkhole (the host-side veth)
		{"ip", "netns", "exec", s.nsName, "ip", "route", "add", "default", "via", "10.200.0.1"},
	}

	for _, cmd := range cmds {
		if err := runCmd(cmd[0], cmd[1:]...); err != nil {
			s.logger.Warn("netns setup command failed (non-fatal)", "cmd", cmd, "error", err)
		}
	}

	s.logger.Info("created isolated network namespace", "name", s.nsName)
	return nil
}

// Listen starts the sinkhole TCP listener to capture connection attempts.
func (s *Sinkhole) Listen(ctx context.Context) {
	addr := fmt.Sprintf("10.200.0.1:%d", s.port)
	var err error
	s.listener, err = net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("sinkhole listen failed", "addr", addr, "error", err)
		return
	}
	defer s.listener.Close()

	s.logger.Info("sinkhole listening", "addr", addr)

	// Also set up iptables to redirect all traffic to sinkhole port
	runCmd("iptables", "-t", "nat", "-A", "PREROUTING",
		"-i", "veth-ksm-h", "-p", "tcp",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", s.port))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Sinkhole) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
	attempt := ConnectionAttempt{
		Timestamp: time.Now(),
		DstAddr:   remoteAddr.IP.String(),
		DstPort:   remoteAddr.Port,
		Family:    4, // IPv4
	}

	// Read initial data (if any)
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	if n > 0 {
		attempt.RawData = make([]byte, n)
		copy(attempt.RawData, buf[:n])
	}

	s.mu.Lock()
	s.connections = append(s.connections, attempt)
	s.mu.Unlock()

	s.logger.Warn("sinkhole captured connection",
		"src", remoteAddr.String(),
		"data_len", n)
}

// GetConnectionAttempts returns all captured connection attempts.
func (s *Sinkhole) GetConnectionAttempts() []ConnectionAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]ConnectionAttempt, len(s.connections))
	copy(result, s.connections)
	return result
}

// Cleanup removes the network namespace and associated resources.
func (s *Sinkhole) Cleanup() {
	if s.listener != nil {
		s.listener.Close()
	}

	// Remove iptables rule
	runCmd("iptables", "-t", "nat", "-D", "PREROUTING",
		"-i", "veth-ksm-h", "-p", "tcp",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", s.port))

	// Remove veth pair (auto-removed with namespace usually)
	runCmd("ip", "link", "del", "veth-ksm-h")

	// Remove namespace
	runCmd("ip", "netns", "del", s.nsName)

	s.logger.Info("cleaned up sinkhole", "namespace", s.nsName)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, string(output))
	}
	return nil
}
