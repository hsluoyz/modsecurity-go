package modsecurity

import (
	"os"
	"strings"
	"testing"
)

func TestBuffer(t *testing.T) {
	var b *buffer
	var err error
	checkBuffer := func(len int64) {
		if b.length != len {
			t.Errorf("unexpected length %d should %d", b.length, len)
		}
		if b.length <= b.memLimit && b.fileBuf != nil {
			t.Errorf("buffer with size %d expect use memory only", b.length)
		}
		if b.length > b.memLimit {
			if b.fileBuf == nil {
				t.Errorf("buffer with size %d expect use file ", b.length)
				return
			}
			_, err := os.Stat(b.fileBuf.Name())
			if err != nil {
				t.Error(err)
			}
		}
	}
	t.Run("memory", func(t *testing.T) {
		b, err = newBuffer("/tmp/modsecurity", 32, 64)
		if err != nil {
			t.Error(err)
			return
		}
		_, err := b.Write([]byte(strings.Repeat("1", 16)))
		if err != nil {
			t.Error(err)
		}
		checkBuffer(16)
		_, err = b.Write([]byte(strings.Repeat("2", 16)))
		if err != nil {
			t.Error(err)
		}
		checkBuffer(32)
		buf := make([]byte, 128)
		nr, err := b.Read(buf)
		if err != nil {
			t.Error(err)
		}
		if nr != 32 {
			t.Errorf("expect reading 32 byte got %d", nr)
		}
		if string(buf[:nr]) != strings.Repeat("1", 16)+strings.Repeat("2", 16) {
			t.Errorf("unexpected content %s", string(buf[:nr]))
		}
	})

	t.Run("file", func(t *testing.T) {
		b, err = newBuffer("/tmp/modsecurity", 32, 64)
		if err != nil {
			t.Error(err)
			return
		}
		_, err := b.Write([]byte(strings.Repeat("1", 32)))
		if err != nil {
			t.Error(err)
		}
		checkBuffer(32)
		_, err = b.Write([]byte(strings.Repeat("2", 32)))
		if err != nil {
			t.Error(err)
		}
		checkBuffer(64)
		buf := make([]byte, 128)
		nr, err := b.Read(buf)
		if err != nil {
			t.Error(err)
		}
		if nr != 64 {
			t.Errorf("expect reading 64 byte got %d", nr)
		}
		if string(buf[:nr]) != strings.Repeat("1", 32)+strings.Repeat("2", 32) {
			t.Errorf("unexpected content %s", string(buf[:nr]))
		}

		str, err := b.String()
		if err != ErrOutOfMemLimit {
			t.Error(err)
		}
		if str != strings.Repeat("1", 32) {
			t.Errorf("unexpected content %s", str)
		}

		buf2, err := b.Bytes()
		if err != ErrOutOfMemLimit {
			t.Error(err)
		}
		if string(buf2) != strings.Repeat("1", 32) {
			t.Errorf("unexpected content %s", string(buf2))
		}

		filename := b.fileBuf.Name()
		_, err = os.Stat(filename)
		if err != nil {
			t.Error(err)
		}
		b.Close()
		_, err = os.Stat(filename)
		if !os.IsNotExist(err) {
			t.Error(err)
		}

	})
}
