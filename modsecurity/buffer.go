package modsecurity

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

func newBuffer(dir string, memLimit, fileLimit int64) (*buffer, error) {
	err := makeBufferDir(dir)
	if err != nil {
		return nil, err
	}
	return &buffer{
		dir:       dir,
		memLimit:  memLimit,
		fileLimit: fileLimit,
		memBuf:    bytes.NewBuffer(nil),
	}, nil
}

type buffer struct {
	dir       string
	length    int64
	memLimit  int64
	fileLimit int64
	memBuf    *bytes.Buffer
	memReader *bytes.Reader
	fileBuf   *os.File
	readed    bool
}

var ErrOutOfFileLimit = errors.New("out of file limit")
var ErrOutOfMemLimit = errors.New("out of memory limit")
var ErrBufferReaded = errors.New("buffer can't write after read")

func (b *buffer) Write(p []byte) (wn int, err error) {
	if b.readed {
		return 0, ErrBufferReaded
	}
	switch {
	case b.length+int64(len(p)) > b.fileLimit:
		return 0, ErrOutOfFileLimit
	case b.fileBuf == nil && b.length+int64(len(p)) > b.memLimit:
		b.memBuf.Write(p[:b.memLimit-b.length])
		b.fileBuf, err = ioutil.TempFile(b.dir, "modsecurity-buffer-*.data")
		if err != nil {
			return 0, err
		}
		_, err = b.fileBuf.Write(b.memBuf.Bytes())
		if err != nil {
			return 0, err
		}
		wn, err = b.fileBuf.Write(p)
	case b.fileBuf == nil:
		wn, err = b.memBuf.Write(p)
	default:
		wn, err = b.fileBuf.Write(p)
	}
	b.length += int64(wn)
	return wn, err
}
func (b *buffer) String() (string, error) {
	var err error
	b.initRead()
	if b.fileBuf != nil {
		err = ErrOutOfMemLimit
	}
	return b.memBuf.String(), err
}
func (b *buffer) Bytes() ([]byte, error) {
	var err error
	b.initRead()
	if b.fileBuf != nil {
		err = ErrOutOfMemLimit
	}
	return b.memBuf.Bytes(), err
}
func (b *buffer) Len() int64 {
	return b.length
}
func (b *buffer) initRead() {
	if !b.readed {
		b.memReader = bytes.NewReader(b.memBuf.Bytes())
		b.fileBuf.Seek(0, 0)
	}
	return
}
func (b *buffer) Read(p []byte) (n int, err error) {
	b.initRead()
	if b.fileBuf == nil {
		return b.memReader.Read(p)
	}
	return b.fileBuf.Read(p)
}
func (b *buffer) WriteTo(w io.Writer) (n int64, err error) {
	b.initRead()
	if b.fileBuf == nil {
		return b.memReader.WriteTo(w)
	}
	return io.Copy(w, b.fileBuf)
}
func (b *buffer) Seek(offset int64, whence int) (int64, error) {
	b.initRead()
	if b.fileBuf == nil {
		return b.memReader.Seek(offset, whence)
	}
	return b.fileBuf.Seek(offset, whence)
}

func (b *buffer) Close() error {
	filename := b.fileBuf.Name()
	err := b.fileBuf.Close()
	err2 := os.Remove(filename)
	switch {
	case err != nil:
		return err
	case err2 != nil:
		return err2
	}
	return nil
}

func makeBufferDir(dir string) error {
	_, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}
