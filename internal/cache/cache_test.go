package cache

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

const testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFpaOUI9V5kHYAYPXYb1sZtilWevnfxnrgNIfNNqVWdv"

func TestKeyNamespace(t *testing.T) {
	if Key("a", "u") == Key("b", "u") {
		t.Fatal("namespace collision")
	}
	if Key("a", "u") == Key("a", "v") {
		t.Fatal("username collision")
	}
}

func TestNormalize(t *testing.T) {
	want := testPublicKey + " comment\n"
	got, err := Normalize([]string{testPublicKey + " comment"})
	if err != nil || string(got) != want {
		t.Fatalf("Normalize() = %q, %v; want %q", got, err, want)
	}
	for _, keys := range [][]string{
		{""},
		{"  "},
		{"not-a-key"},
		{testPublicKey + "\n" + testPublicKey},
	} {
		if _, err := Normalize(keys); err == nil {
			t.Fatalf("Normalize(%q) accepted invalid entry", keys)
		}
	}
	if got, err := Normalize(nil); err != nil || len(got) != 0 {
		t.Fatalf("Normalize(nil) = %q, %v", got, err)
	}
}

func TestReadWriteEmptyAndPositive(t *testing.T) {
	dir := secureTempDir(t)
	key := Key("test", "alice")

	entry, err := Read(dir, key)
	if err != nil || entry.Exists {
		t.Fatalf("missing Read() = %+v, %v", entry, err)
	}
	for _, data := range [][]byte{nil, []byte("complete cache value\n")} {
		if err := Write(dir, key, data); err != nil {
			t.Fatal(err)
		}
		entry, err = Read(dir, key)
		if err != nil || !entry.Exists || !bytes.Equal(entry.Data, data) {
			t.Fatalf("Read() = %+v, %v; want %q", entry, err, data)
		}
	}
	if _, err := Read(dir, "../escape"); err == nil {
		t.Fatal("invalid cache key accepted")
	}
}

func TestValidateDir(t *testing.T) {
	dir := secureTempDir(t)
	if err := ValidateDir(dir); err != nil {
		t.Fatalf("safe directory rejected: %v", err)
	}
	for _, mode := range []os.FileMode{0755, 0770} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := ValidateDir(dir); err == nil {
			t.Fatalf("directory mode %04o accepted", mode)
		}
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}

	link := dir + "-link"
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(link)
	if err := ValidateDir(link); err == nil {
		t.Fatal("symlink directory accepted")
	}
}

func TestLockTimeout(t *testing.T) {
	dir := secureTempDir(t)
	key := Key("test", "alice")
	first, err := Lock(dir, key, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	started := time.Now()
	if _, err := Lock(dir, key, 30*time.Millisecond); err == nil {
		t.Fatal("second lock unexpectedly succeeded")
	}
	if elapsed := time.Since(
		started,
	); elapsed < 20*time.Millisecond ||
		elapsed > 250*time.Millisecond {
		t.Fatalf("lock wait was %v", elapsed)
	}
}

func TestAtomicWriteConcurrentReaders(t *testing.T) {
	dir := secureTempDir(t)
	key := Key("test", "alice")
	oldData := bytes.Repeat([]byte("old\n"), 1024)
	newData := bytes.Repeat([]byte("new\n"), 1024)
	if err := Write(dir, key, oldData); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 8)
	done := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				entry, err := Read(dir, key)
				if err != nil {
					errCh <- err
					return
				}
				if !bytes.Equal(entry.Data, oldData) && !bytes.Equal(entry.Data, newData) {
					errCh <- fmt.Errorf("reader observed partial cache data: size=%d", len(entry.Data))
					return
				}
			}
		}()
	}
	for i := 0; i < 30; i++ {
		data := oldData
		if i%2 == 0 {
			data = newData
		}
		if err := Write(dir, key, data); err != nil {
			t.Fatal(err)
		}
	}
	close(done)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
