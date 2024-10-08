package tls

import (
	"bytes"
	"context"
	"net"
)

// KccolGateWayIn role for receive msg from client

type KccolGateWayIn struct {
	conn     net.Conn
	recorder *KccolTLSRecorder
	err      error
	cancel   context.CancelFunc
	WaitOut  chan bool
}

func NewKccolGateWayIn(conn net.Conn, recordHandler KccolTLSRecorderHandler, cancelFunc context.CancelFunc) *KccolGateWayIn {
	return &KccolGateWayIn{
		conn:     conn,
		recorder: NewKccolTLSRecorder(conn, recordHandler),
		cancel:   cancelFunc,
		WaitOut:  make(chan bool, 1),
	}

}

func (ki *KccolGateWayIn) setError(err error) error {
	ki.err = err
	ki.cancel()
	return ki.err
}

func (ki *KccolGateWayIn) getErr() error {
	return ki.err
}

func (ki *KccolGateWayIn) StartRecord(context context.Context, k *KccolGateWay) error {
	rawInBuf := ki.GetRawInBuf()
	for {
		recordLen, err := ki.recorder.ReadRecord(context)
		if err != nil {
			return ki.setError(err)
		}
		err = k.out.Write(rawInBuf.Next(recordLen))
		if err != nil {
			return ki.setError(err)
		}
	}
}

func (ki *KccolGateWayIn) StopRecord() error {
	err := ki.conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (ki *KccolGateWayIn) Write(bytes []byte) error {
	_, err := ki.conn.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func (ki *KccolGateWayIn) GetRawInBuf() *bytes.Buffer {
	return ki.recorder.GetRawInBuf()
}
