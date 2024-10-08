package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"net"
)

// KccolGateWayIn role for receive msg from client

type KccolGateWayIn struct {
	conn          net.Conn
	recorder      *KccolTLSRecorder
	err           error
	cancel        context.CancelFunc
	realInHandler KccolRealHandler
	WaitOut       chan bool
	WaitOutReal   chan bool
}

func NewKccolGateWayIn(conn net.Conn, recordHandler KccolTLSRecorderHandler, realInHandler KccolRealHandler, cancelFunc context.CancelFunc) *KccolGateWayIn {
	return &KccolGateWayIn{
		conn:          conn,
		realInHandler: realInHandler,
		recorder:      NewKccolTLSRecorder(conn, recordHandler),
		cancel:        cancelFunc,
		WaitOut:       make(chan bool, 1),
		WaitOutReal:   make(chan bool, 1),
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
		if k.out.isUsedRealConn {
			var record []byte = nil
			record, err = decryptBySessionId(rawInBuf.Next(recordLen), k.sessionId)
			if err != nil {
				return err
			}
			if k.in.realInHandler != nil {
				err = k.in.realInHandler.HandleRawRecord(context, record)
				if err != nil {
					return err
				}
			}
			_, err = k.out.realConn.Write(record)
		} else {
			err = k.out.Write(rawInBuf.Next(recordLen))
		}

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

func decryptBySessionId(record []byte, sessionId []byte) ([]byte, error) {
	ciphertext := record[recordHeaderLen:]
	// 1. 创建 AES 块加密器
	block, err := aes.NewCipher(sessionId)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// 2. 创建 GCM 实例
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// 3. 提取 nonce（前 12 字节）
	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// 4. 使用 AES-GCM 解密数据并提供 additionalData 进行验证
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil

}
