package tls

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
)

type KccolGateWayOut struct {
	serverName     string
	sessionId      []byte
	conn           net.Conn
	connNeedCancel bool
	realConn       net.Conn
	initRealConnFn func(context.Context) (net.Conn, error)
	isUsedRealConn bool
	recorder       *KccolTLSRecorder
	cryptoReader   *KccolCryptoWriter
	realOutHandler KccolRealHandler
	err            error
	cancel         context.CancelFunc
}

type KccolRealHandler interface {
	HandleRawRecord(context context.Context, recordPayload []byte) error
}

func NewKccolGateWayOut(serverName string, sessionId []byte, initRealConnFn func(context.Context) (net.Conn, error), cancelFunc context.CancelFunc) *KccolGateWayOut {
	return &KccolGateWayOut{
		serverName:     serverName,
		cancel:         cancelFunc,
		isUsedRealConn: false,
		initRealConnFn: initRealConnFn,
		sessionId:      sessionId,
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
	ko.connNeedCancel = false
	ko.recorder = NewKccolTLSRecorder(conn, handler)
	return nil
}

func (ko *KccolGateWayOut) HandleRawData(context context.Context, payload []byte) error {
	return ko.realOutHandler.HandleRawRecord(context, payload)
}

func (ko *KccolGateWayOut) ReInitRealConn(context context.Context, handler KccolRealHandler) error {
	ko.connNeedCancel = true
	err := ko.conn.Close()
	if err != nil {
		return ko.setError(err)
	}
	if ko.initRealConnFn == nil {
		return ko.setError(errors.New("InitRealConnFn is nil"))
	}
	conn, err := ko.initRealConnFn(context)
	if conn == nil {
		return ko.setError(errors.New("InitRealConnFn result conn is nil"))
	}
	ko.conn = nil
	ko.realConn = conn
	ko.isUsedRealConn = true
	ko.realOutHandler = handler
	return nil
}

func (ko *KccolGateWayOut) IsUsedRealConn() bool {
	return ko.isUsedRealConn
}

func (ko *KccolGateWayOut) StartRecord(context context.Context, k *KccolGateWay) error {
	rawOutBuf := ko.getRawOutBuf()
	for {
		recorder := ko.recorder
		recordLen, err := recorder.ReadRecord(context)
		if err != nil && !ko.connNeedCancel {
			return ko.setError(err)
		}
		err = k.in.Write(rawOutBuf.Next(recordLen))
		if err != nil {
			return ko.setError(err)
		}
	}
}

func (ko *KccolGateWayOut) StartRealRecord(context context.Context, k *KccolGateWay) error {
	ko.cryptoReader = NewKccolCryptoReader(context, ko.realConn, k.sessionId, k.clientHelloMsg.vers, ko)
	_, err := io.Copy(k.in.conn, ko.cryptoReader)
	if err != nil {
		return err
	}
	return nil
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

func (ko *KccolGateWayOut) getRawOutBuf() *bytes.Buffer {
	return ko.recorder.GetRawInBuf()
}
