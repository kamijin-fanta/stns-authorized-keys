package cache

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

type Entry struct {
	Data    []byte
	ModTime time.Time
	Exists  bool
}

func Key(namespace, user string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(namespace+"\x00"+user)))
}

func validKey(key string) bool {
	if len(key) != sha256.Size*2 {
		return false
	}
	for _, r := range key {
		if !('0' <= r && r <= '9' || 'a' <= r && r <= 'f') {
			return false
		}
	}
	return true
}

func ValidateDir(path string) error {
	fi, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache directory invalid")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("cache directory owner mismatch")
	}
	if fi.Mode().Perm() != 0700 {
		return fmt.Errorf("cache directory permissions must be 0700")
	}
	return nil
}
func Read(dir, key string) (Entry, error) {
	if !validKey(key) {
		return Entry{}, fmt.Errorf("invalid cache key")
	}
	p := filepath.Join(dir, key+".keys")
	if _, e := os.Lstat(p); os.IsNotExist(e) {
		return Entry{}, nil
	} else if e != nil {
		return Entry{}, e
	}
	f, e := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return Entry{}, e
	}
	defer f.Close()
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
		return Entry{}, fmt.Errorf("cache file permissions or type invalid")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		return Entry{}, fmt.Errorf("cache file owner invalid")
	}
	b, e := io.ReadAll(f)
	if e != nil {
		return Entry{}, e
	}
	return Entry{Data: b, ModTime: fi.ModTime(), Exists: true}, nil
}
func Write(dir, key string, data []byte) error {
	if !validKey(key) {
		return fmt.Errorf("invalid cache key")
	}
	if err := ValidateDir(dir); err != nil {
		return err
	}
	f, e := os.CreateTemp(dir, ".stns-*.tmp")
	if e != nil {
		return e
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Chmod(0600); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(tmp, filepath.Join(dir, key+".keys")); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e == nil {
		e = d.Sync()
		d.Close()
	}
	if e != nil {
		return e
	}
	ok = true
	return nil
}
func Normalize(keys []string) ([]byte, error) {
	var out strings.Builder
	for _, k := range keys {
		if strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("empty authorized key")
		}
		k = strings.TrimSpace(k)
		_, _, _, rest, e := ssh.ParseAuthorizedKey([]byte(k + "\n"))
		if e != nil || strings.TrimSpace(string(rest)) != "" {
			if e == nil {
				e = fmt.Errorf("multiple authorized keys in one entry")
			}
			return nil, e
		}
		out.WriteString(k)
		out.WriteByte('\n')
	}
	return []byte(out.String()), nil
}

type Locker struct{ f *os.File }

func Lock(dir, key string, wait time.Duration) (*Locker, error) {
	if !validKey(key) {
		return nil, fmt.Errorf("invalid cache key")
	}
	f, e := os.OpenFile(
		filepath.Join(dir, key+".lock"),
		os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,
		0600,
	)
	if e != nil {
		return nil, e
	}
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0600 {
		f.Close()
		return nil, fmt.Errorf("lock file invalid")
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() {
		f.Close()
		return nil, fmt.Errorf("lock owner invalid")
	}
	deadline := time.Now().Add(wait)
	for {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			return &Locker{f}, nil
		}
		if e != syscall.EWOULDBLOCK && e != syscall.EAGAIN {
			f.Close()
			return nil, e
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, e
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (l *Locker) Close() {
	if l != nil && l.f != nil {
		syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
		l.f.Close()
	}
}
