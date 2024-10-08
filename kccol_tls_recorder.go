package tls

import (
	"bytes"
	"context"
	"io"
	"net"
)

type KccolTLSRecorder struct {
	conn         net.Conn
	headerBuffer bytes.Buffer
	recordBuffer bytes.Buffer
	rawInput     bytes.Buffer
	handler      KccolTLSRecorderHandler
}

type KccolTLSRecorderHandler interface {
	HandleRawRecord(context context.Context, recordHeader []byte, recordPayload []byte) error
}

func NewKccolTLSRecorder(conn net.Conn, handler KccolTLSRecorderHandler) *KccolTLSRecorder {
	return &KccolTLSRecorder{
		conn:    conn,
		handler: handler,
	}
}

// ReadRecord return record len
func (ki *KccolTLSRecorder) ReadRecord(ctx context.Context) (int, error) {
	// Read header, payload.
	if err := ki.readFromUntilHeader(); err != nil {
		return 0, err
	}
	hdr := ki.headerBuffer.Next(recordHeaderLen)
	n := int(hdr[3])<<8 | int(hdr[4])
	//do sth with record header
	if err := ki.readFromUntilRecordLayer(n); err != nil {
		return 0, err
	}
	record := ki.recordBuffer.Next(n)
	//do sth with record
	if ki.handler != nil {
		err := ki.handler.HandleRawRecord(ctx, hdr, record)
		if err != nil {
			return 0, err
		}
	}
	return recordHeaderLen + n, nil
}

func (ki *KccolTLSRecorder) writeToHeaderBuffer(bytes []byte) {
	ki.headerBuffer.Grow(recordHeaderLen)
	ki.headerBuffer.Write(bytes)
}

func (ki *KccolTLSRecorder) writeToRecordBuffer(bytes []byte) {
	ki.recordBuffer.Grow(len(bytes))
	ki.recordBuffer.Write(bytes)
}

func (ki *KccolTLSRecorder) readFromUntilHeader() error {
	err := ki.readFromUntil(ki.conn, recordHeaderLen)
	if err != nil {
		return err
	}
	ki.writeToHeaderBuffer(ki.rawInput.Bytes()[0:recordHeaderLen])
	return nil
}

func (ki *KccolTLSRecorder) readFromUntilRecordLayer(recordLen int) error {
	err := ki.readFromUntil(ki.conn, recordHeaderLen+recordLen)
	if err != nil {
		return err
	}
	ki.writeToRecordBuffer(ki.rawInput.Bytes()[recordHeaderLen : recordHeaderLen+recordLen])

	return nil
}

// readFromUntil reads from r into c.rawInput until c.rawInput contains
// at least n bytes or else returns an error.
func (ki *KccolTLSRecorder) readFromUntil(r io.Reader, n int) error {
	if ki.rawInput.Len() >= n {
		return nil
	}
	needs := n - ki.rawInput.Len()
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	ki.rawInput.Grow(needs + bytes.MinRead)
	_, err := ki.rawInput.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}

func (ki *KccolTLSRecorder) GetRawInBuf() *bytes.Buffer {
	return &ki.rawInput
}
