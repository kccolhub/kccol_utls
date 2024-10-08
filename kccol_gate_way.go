package tls

import (
	"awesomeProject/config"
	"awesomeProject/logger"
	"context"
	"errors"
	"net"
)

type KccolGateWay struct {
	clientHelloMsg   *ClientHelloMsg
	sessionId        []byte
	in               *KccolGateWayIn
	out              *KccolGateWayOut
	cancelFunc       context.CancelFunc
	inHandler        KccolTLSRecorderHandler
	outHandler       KccolTLSRecorderHandler
	realOutHandler   KccolRealHandler
	gateWayHandshake bool
}

type KccolGateWayInHandler struct {
	kccolGateWay *KccolGateWay
	KccolTLSRecorderHandler
}

type KccolGateWayOutHandler struct {
	kccolGateWay *KccolGateWay
	KccolTLSRecorderHandler
}

func (handler *KccolGateWayInHandler) HandleRawRecord(context context.Context, recordHeader []byte, recordPayload []byte) error {
	typ := RecordType(recordHeader[0])
	if typ == recordTypeHandshake && recordPayload[0] == typeClientHello {
		clientHelloMsg := new(ClientHelloMsg)
		clientHelloMsg.unmarshal(recordPayload)
		handler.kccolGateWay.clientHelloMsg = clientHelloMsg
		handler.kccolGateWay.sessionId = make([]byte, len(clientHelloMsg.sessionId))
		copy(handler.kccolGateWay.sessionId, clientHelloMsg.sessionId)
		handler.kccolGateWay.out = NewKccolGateWayOut(clientHelloMsg.serverName, handler.kccolGateWay.sessionId, handler.kccolGateWay.initRealConn, handler.kccolGateWay.cancelFunc)
		go func() {
			out := handler.kccolGateWay.out
			err := out.Init(&KccolGateWayOutHandler{
				kccolGateWay: handler.kccolGateWay,
			})
			if err != nil {
				handler.kccolGateWay.in.WaitOut <- false
				out.cancel()
				return
			}
			handler.kccolGateWay.in.WaitOut <- true
			for {
				err = out.StartRecord(context, handler.kccolGateWay)
				if err != nil {
					break
				}
			}
			if !handler.kccolGateWay.out.connNeedCancel {
				out.cancel()
			}
		}()
		waitOutResult := <-handler.kccolGateWay.in.WaitOut
		if !waitOutResult {
			return errors.New("kccolGateWay make out failed")
		}
	} else if typ == RecordTypeApplicationData && !handler.kccolGateWay.gateWayHandshake {
		go func() {
			out := handler.kccolGateWay.out
			defer out.cancel()
			err := out.ReInitRealConn(context, handler.kccolGateWay.realOutHandler)
			if err != nil {
				handler.kccolGateWay.in.WaitOutReal <- false
				return
			}
			handler.kccolGateWay.in.WaitOutReal <- true
			for {
				err = out.StartRealRecord(context, handler.kccolGateWay)
				if err != nil {
					break
				}
			}

		}()
		waitOutRealResult := <-handler.kccolGateWay.in.WaitOutReal
		handler.kccolGateWay.gateWayHandshake = waitOutRealResult
		if !waitOutRealResult {
			return errors.New("kccolGateWay make out failed")
		}
	}
	if handler.kccolGateWay.inHandler != nil {
		err := handler.kccolGateWay.inHandler.HandleRawRecord(context, recordHeader, recordPayload)
		if err != nil {
			return err
		}
	}
	return nil
}
func (handler *KccolGateWayOutHandler) HandleRawRecord(context context.Context, recordHeader []byte, recordPayload []byte) error {
	if handler.kccolGateWay.outHandler != nil {
		err := handler.kccolGateWay.outHandler.HandleRawRecord(context, recordHeader, recordPayload)
		if err != nil {
			return err
		}
	}
	return nil
}

func NewKccolGateWay() *KccolGateWay {
	result := &KccolGateWay{
		gateWayHandshake: false,
	}
	return result
}

func (k *KccolGateWay) StartGateWay(ctx context.Context, conn net.Conn, inHandler KccolTLSRecorderHandler, outHandler KccolTLSRecorderHandler, realInHandler KccolRealHandler, realOutHandler KccolRealHandler) (ret error, realErr error) {
	ctx, cancel := context.WithCancel(ctx)
	k.in = NewKccolGateWayIn(conn,
		&KccolGateWayInHandler{
			kccolGateWay: k,
		}, realInHandler, cancel)
	k.cancelFunc = cancel
	k.inHandler = inHandler
	k.outHandler = outHandler
	k.realOutHandler = realOutHandler
	defer cancel()
	if ctx.Done() != nil {
		// Start the "interrupter" goroutine, if this context might be canceled.
		// (The background context cannot).
		//
		// The interrupter goroutine waits for the input context to be done and
		// closes the connection if this happens before the function returns.
		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			close(done)
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()
		go func() {
			select {
			case <-ctx.Done():
				// Close the connection, discarding the error
				_, _ = k.closeGateWay()
				interruptRes <- ctx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}
	for {
		err := k.in.StartRecord(ctx, k)
		if err != nil {
			return ret, err
		}
	}
}

func (k *KccolGateWay) initRealConn(context context.Context) (net.Conn, error) {
	addr := config.GetProxyServerAddr()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	logger.GetNLogger().Info("initRealConn")
	return conn, err
}

func (k *KccolGateWay) closeGateWay() (error, error) {
	var err1 error = nil
	var err2 error = nil
	if k.in != nil && k.in.conn != nil {
		err1 = k.in.conn.Close()
	}
	if k.out != nil && k.out.conn != nil {
		err2 = k.out.conn.Close()
	}
	return err1, err2
}

func (k *KccolGateWay) GetError() (inErr error, outErr error) {
	return k.in.getErr(), k.in.getErr()
}

func (k *KccolGateWay) GetClientHello() *ClientHelloMsg {
	return k.clientHelloMsg
}

func (k *KccolGateWay) GetServerName() string {
	if k.clientHelloMsg != nil {
		return k.clientHelloMsg.serverName
	}
	return ""
}

func (k *KccolGateWay) GetInAddr() (net.Addr, net.Addr) {
	if k.in != nil && k.in.conn != nil {
		return k.in.conn.LocalAddr(), k.in.conn.RemoteAddr()
	}
	return nil, nil
}

func (k *KccolGateWay) GetOutAddr() (net.Addr, net.Addr) {
	if k.out != nil && k.out.conn != nil {
		return k.out.conn.LocalAddr(), k.out.conn.RemoteAddr()
	}
	return nil, nil
}

func (k *KccolGateWay) GetOutRealAddr() (net.Addr, net.Addr) {
	if k.out != nil && k.out.realConn != nil {
		return k.out.realConn.LocalAddr(), k.out.realConn.RemoteAddr()
	}
	return nil, nil
}

func (k *KccolGateWay) IsRealConnecting() bool {
	return k.out.isUsedRealConn
}
