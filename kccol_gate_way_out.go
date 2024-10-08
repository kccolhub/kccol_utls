package tls

import (
	"bytes"
	"context"
	"net"
)

type KccolGateWayOut struct {
	serverName string
	conn       net.Conn
	recorder   *KccolTLSRecorder
	err        error
	cancel     context.CancelFunc
}

func NewKccolGateWayOut(serverName string, cancelFunc context.CancelFunc) *KccolGateWayOut {
	return &KccolGateWayOut{
		serverName: serverName,
		cancel:     cancelFunc,
	}
}

func (ko *KccolGateWayOut) setError(err error) error {
	ko.err = err
	ko.cancel()
	return ko.err
}

func (ko *KccolGateWayOut) getError() error {
	return ko.err
}

func (ko *KccolGateWayOut) Init(handler KccolTLSRecorderHandler) error {
	conn, err := net.Dial("tcp", ko.serverName+":443")
	if err != nil {
		return ko.setError(err)
	}
	ko.conn = conn
	ko.recorder = NewKccolTLSRecorder(conn, handler)
	return nil
}

func (ko *KccolGateWayOut) StartRecord(context context.Context, k *KccolGateWay) error {
	rawOutBuf := ko.GetRawOutBuf()
	for {
		recordLen, err := ko.recorder.ReadRecord(context)
		if err != nil {
			return ko.setError(err)
		}
		err = k.in.Write(rawOutBuf.Next(recordLen))
		if err != nil {
			return ko.setError(err)
		}
	}
}

func (ko *KccolGateWayOut) StopRecord() error {
	err := ko.conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (ko *KccolGateWayOut) Write(bytes []byte) error {
	_, err := ko.conn.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func (ko *KccolGateWayOut) GetRawOutBuf() *bytes.Buffer {
	return ko.recorder.GetRawInBuf()
}
