package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxEntries = 64
	maxBytes   = 4 << 20
	maxMessage = 1 << 20
)

type request struct {
	Op          string            `json:"op"`
	Key         string            `json:"key,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Unset       []string          `json:"unset,omitempty"`
	TTL         int64             `json:"ttl_seconds,omitempty"`
}
type response struct {
	OK          bool              `json:"ok"`
	Found       bool              `json:"found,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Unset       []string          `json:"unset,omitempty"`
	Error       string            `json:"error,omitempty"`
}
type entry struct {
	environment map[string]string
	unset       []string
	expires     time.Time
	bytes       int
}
type cache struct {
	sync.Mutex
	entries map[string]entry
	bytes   int
	locked  bool
}

func SocketPath() (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		var err error
		base, err = os.UserCacheDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(base, "dotenvsec")
	} else {
		base = filepath.Join(base, "dotenvsec")
	}
	if err := secureDirectory(base); err != nil {
		return "", err
	}
	return filepath.Join(base, "agent.sock"), nil
}

func Serve() error {
	path, err := SocketPath()
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to replace non-socket agent path")
		}
		if conn, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			return errors.New("agent is already running")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	defer func() { _ = os.Remove(path) }()
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	state := &cache{entries: map[string]entry{}}
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go state.handle(connection)
	}
}

func (c *cache) handle(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	if err := verifyPeer(connection); err != nil {
		return
	}
	decoder := json.NewDecoder(bufio.NewReaderSize(connection, maxMessage))
	decoder.DisallowUnknownFields()
	var req request
	if err := decoder.Decode(&req); err != nil {
		encode(connection, response{Error: "invalid request"})
		return
	}
	c.Lock()
	defer c.Unlock()
	c.expire()
	switch req.Op {
	case "get":
		if c.locked {
			encode(connection, response{OK: true})
			return
		}
		item, ok := c.entries[req.Key]
		if !ok {
			encode(connection, response{OK: true})
			return
		}
		encode(connection, response{OK: true, Found: true, Environment: cloneMap(item.environment), Unset: append([]string(nil), item.unset...)})
	case "put":
		if c.locked || req.TTL <= 0 {
			encode(connection, response{OK: true})
			return
		}
		bytes := envBytes(req.Environment)
		if bytes > maxBytes {
			encode(connection, response{Error: "entry too large"})
			return
		}
		if old, ok := c.entries[req.Key]; ok {
			c.bytes -= old.bytes
			zero(old.environment)
		}
		for (len(c.entries) >= maxEntries || c.bytes+bytes > maxBytes) && len(c.entries) > 0 {
			c.evictOldest()
		}
		c.entries[req.Key] = entry{cloneMap(req.Environment), append([]string(nil), req.Unset...), time.Now().Add(time.Duration(req.TTL) * time.Second), bytes}
		c.bytes += bytes
		encode(connection, response{OK: true})
	case "flush":
		c.flush()
		encode(connection, response{OK: true})
	case "lock":
		c.flush()
		c.locked = true
		encode(connection, response{OK: true})
	default:
		encode(connection, response{Error: "unsupported operation"})
	}
}

func Client(op, key string, environment map[string]string, unset []string, ttl time.Duration) (map[string]string, []string, bool, error) {
	path, err := SocketPath()
	if err != nil {
		return nil, nil, false, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, false, err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, false, errors.New("unsafe agent socket")
	}
	connection, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { _ = connection.Close() }()
	if err := verifyPeer(connection); err != nil {
		return nil, nil, false, err
	}
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	req := request{op, key, environment, unset, int64(ttl / time.Second)}
	if err := json.NewEncoder(connection).Encode(req); err != nil {
		return nil, nil, false, err
	}
	var resp response
	decoder := json.NewDecoder(connection)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&resp); err != nil {
		return nil, nil, false, err
	}
	if resp.Error != "" {
		return nil, nil, false, errors.New(resp.Error)
	}
	return resp.Environment, resp.Unset, resp.Found, nil
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return fmt.Errorf("unsafe agent runtime directory %s", path)
	}
	return nil
}
func (c *cache) expire() {
	now := time.Now()
	for key, item := range c.entries {
		if !now.Before(item.expires) {
			c.bytes -= item.bytes
			zero(item.environment)
			delete(c.entries, key)
		}
	}
}
func (c *cache) evictOldest() {
	var key string
	var oldest time.Time
	for candidate, item := range c.entries {
		if key == "" || item.expires.Before(oldest) {
			key, oldest = candidate, item.expires
		}
	}
	item := c.entries[key]
	c.bytes -= item.bytes
	zero(item.environment)
	delete(c.entries, key)
}
func (c *cache) flush() {
	for key, item := range c.entries {
		zero(item.environment)
		delete(c.entries, key)
	}
	c.bytes = 0
}
func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func envBytes(values map[string]string) int {
	n := 0
	for k, v := range values {
		n += len(k) + len(v)
	}
	return n
}
func zero(values map[string]string) {
	for k := range values {
		values[k] = ""
		delete(values, k)
	}
}
func encode(connection net.Conn, value response) { _ = json.NewEncoder(connection).Encode(value) }
