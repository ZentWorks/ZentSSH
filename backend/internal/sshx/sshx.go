package sshx

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Host        string
	Port        int
	User        string
	AuthType    string
	Password    string
	PrivateKey  string
	Passphrase  string
	Certificate string
	Timeout     time.Duration
	HostKey     ssh.HostKeyCallback
}

type HostKeyInfo struct {
	Algorithm   string `json:"algorithm"`
	KeyBase64   string `json:"keyBase64"`
	Fingerprint string `json:"fingerprint"`
}

func Client(c Config) (*ssh.Client, error) {
	cfg, err := clientConfig(c)
	if err != nil {
		return nil, err
	}
	return ssh.Dial("tcp", address(c.Host, c.Port), cfg)
}

func ClientVia(jump *ssh.Client, c Config) (*ssh.Client, error) {
	if jump == nil {
		return nil, errors.New("jump host client is nil")
	}
	cfg, err := clientConfig(c)
	if err != nil {
		return nil, err
	}
	addr := address(c.Host, c.Port)
	conn, err := jump.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("jump host dial %s: %w", addr, err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

func clientConfig(c Config) (*ssh.ClientConfig, error) {
	if strings.TrimSpace(c.User) == "" {
		return nil, errors.New("SSH username is required")
	}
	if c.Port <= 0 {
		c.Port = 22
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.HostKey == nil {
		return nil, errors.New("SSH host-key verification callback is required")
	}
	auth, err := authMethods(c)
	if err != nil {
		return nil, err
	}
	if len(auth) == 0 {
		return nil, errors.New("no SSH authentication method configured")
	}
	return &ssh.ClientConfig{
		User:            c.User,
		Auth:            auth,
		HostKeyCallback: c.HostKey,
		Timeout:         c.Timeout,
	}, nil
}

func authMethods(c Config) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	typ := strings.TrimSpace(c.AuthType)
	if typ == "" {
		if c.PrivateKey != "" {
			typ = "key"
		} else {
			typ = "password"
		}
	}
	switch typ {
	case "key", "private-key":
		if strings.TrimSpace(c.PrivateKey) == "" {
			return nil, errors.New("private key is empty")
		}
		var signer ssh.Signer
		var err error
		if c.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(c.PrivateKey), []byte(c.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(c.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		if strings.TrimSpace(c.Certificate) != "" {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.Certificate))
			if err != nil {
				return nil, fmt.Errorf("parse OpenSSH certificate: %w", err)
			}
			cert, ok := pub.(*ssh.Certificate)
			if !ok {
				return nil, errors.New("configured certificate is not an OpenSSH user certificate")
			}
			signer, err = ssh.NewCertSigner(cert, signer)
			if err != nil {
				return nil, fmt.Errorf("combine certificate and private key: %w", err)
			}
		}
		auth = append(auth, ssh.PublicKeys(signer))
	case "keyboard-interactive":
		if c.Password == "" {
			return nil, errors.New("keyboard-interactive secret is empty")
		}
		auth = append(auth, ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range questions {
				if i < len(echos) && echos[i] {
					answers[i] = ""
				} else {
					answers[i] = c.Password
				}
			}
			return answers, nil
		}))
	case "password":
		if c.Password == "" {
			return nil, errors.New("password is empty")
		}
		auth = append(auth, ssh.Password(c.Password))
	default:
		return nil, fmt.Errorf("unsupported SSH authentication type %q", typ)
	}
	return auth, nil
}

func HostKeyCallback(info HostKeyInfo) (ssh.HostKeyCallback, error) {
	raw, err := base64.RawStdEncoding.DecodeString(info.KeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode trusted host key: %w", err)
	}
	trusted, err := ssh.ParsePublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse trusted host key: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if trusted.Type() != key.Type() || !bytes.Equal(trusted.Marshal(), key.Marshal()) {
			return fmt.Errorf("SSH host key changed for %s: expected %s, got %s", hostname, info.Fingerprint, ssh.FingerprintSHA256(key))
		}
		return nil
	}, nil
}

func ScanHostKey(host string, port int, timeout time.Duration) (HostKeyInfo, error) {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	conn, err := net.DialTimeout("tcp", address(host, port), timeout)
	if err != nil {
		return HostKeyInfo{}, err
	}
	defer conn.Close()
	return scanConn(conn, address(host, port), timeout)
}

func ScanHostKeyVia(jump *ssh.Client, host string, port int, timeout time.Duration) (HostKeyInfo, error) {
	if jump == nil {
		return HostKeyInfo{}, errors.New("jump host client is nil")
	}
	conn, err := jump.Dial("tcp", address(host, port))
	if err != nil {
		return HostKeyInfo{}, err
	}
	defer conn.Close()
	if deadline, ok := conn.(interface{ SetDeadline(time.Time) error }); ok && timeout > 0 {
		_ = deadline.SetDeadline(time.Now().Add(timeout))
	}
	return scanConn(conn, address(host, port), timeout)
}

var errHostKeyCaptured = errors.New("host key captured")

func scanConn(conn net.Conn, addr string, timeout time.Duration) (HostKeyInfo, error) {
	var captured ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User:    "zentssh-hostkey-probe",
		Timeout: timeout,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			captured = key
			return errHostKeyCaptured
		},
	}
	_, _, _, err := ssh.NewClientConn(conn, addr, cfg)
	if captured == nil {
		if err == nil {
			return HostKeyInfo{}, errors.New("SSH server did not provide a host key")
		}
		return HostKeyInfo{}, err
	}
	return HostKeyInfo{
		Algorithm:   captured.Type(),
		KeyBase64:   base64.RawStdEncoding.EncodeToString(captured.Marshal()),
		Fingerprint: ssh.FingerprintSHA256(captured),
	}, nil
}

func Shell(cl *ssh.Client, term string, cols, rows int) (*ssh.Session, io.WriteCloser, io.Reader, error) {
	s, e := cl.NewSession()
	if e != nil {
		return nil, nil, nil, e
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if e = s.RequestPty(term, rows, cols, modes); e != nil {
		s.Close()
		return nil, nil, nil, e
	}
	in, e := s.StdinPipe()
	if e != nil {
		s.Close()
		return nil, nil, nil, e
	}
	out, e := s.StdoutPipe()
	if e != nil {
		s.Close()
		return nil, nil, nil, e
	}
	s.Stderr = s.Stdout
	if e = s.Shell(); e != nil {
		s.Close()
		return nil, nil, nil, e
	}
	return s, in, out, nil
}

func SFTP(cl *ssh.Client) (*sftp.Client, error) { return sftp.NewClient(cl) }

type Entry struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	Mode    string    `json:"mode"`
	ModTime time.Time `json:"modTime"`
	Dir     bool      `json:"dir"`
	UID     int       `json:"uid"`
	GID     int       `json:"gid"`
}

func List(c *sftp.Client, p string) ([]Entry, error) {
	xs, e := c.ReadDir(p)
	if e != nil {
		return nil, e
	}
	out := make([]Entry, 0, len(xs))
	for _, x := range xs {
		uid, gid := -1, -1
		if stat, ok := x.Sys().(*sftp.FileStat); ok && stat != nil {
			uid = int(stat.UID)
			gid = int(stat.GID)
		}
		out = append(out, Entry{Name: x.Name(), Path: filepath.ToSlash(filepath.Join(p, x.Name())), Size: x.Size(), Mode: x.Mode().String(), ModTime: x.ModTime(), Dir: x.IsDir(), UID: uid, GID: gid})
	}
	return out, nil
}

func Download(c *sftp.Client, p string, w io.Writer) error {
	f, e := c.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = io.Copy(w, f)
	return e
}

func Upload(c *sftp.Client, p string, r io.Reader) error {
	f, e := c.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = io.Copy(f, r)
	return e
}

func Probe(host string, port int) bool {
	conn, e := net.DialTimeout("tcp", address(host, port), 1500*time.Millisecond)
	if e != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func address(host string, port int) string {
	if port <= 0 {
		port = 22
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
