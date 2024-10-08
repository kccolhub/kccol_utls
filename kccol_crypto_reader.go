package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"net"
)

type KccolCryptoWriter struct {
	context    context.Context
	tlsVersion uint16
	conn       net.Conn
	key        []byte
	io.Reader
	listener KccolCryptoReaderListener
	Rand     io.Reader
}

type KccolCryptoReaderListener interface {
	HandleRawData(context.Context, []byte) error
}

func NewKccolCryptoReader(context context.Context, conn net.Conn, key []byte, tlsVersion uint16, listener KccolCryptoReaderListener) *KccolCryptoWriter {
	return &KccolCryptoWriter{
		context:    context,
		conn:       conn,
		key:        key,
		tlsVersion: tlsVersion,
		listener:   listener,
	}
}
func (k *KccolCryptoWriter) Read(p []byte) (n int, err error) {
	size, err := k.conn.Read(p)
	if k.listener != nil {
		err = k.listener.HandleRawData(k.context, p[:size])
		if err != nil {
			return 0, err
		}
	}
	result, err := k.encryptBySessionId(p[:size], k.key, k.rand())
	p = p[:0]
	p = append(p, result...)
	return len(result), err
}

func (k *KccolCryptoWriter) rand() io.Reader {
	r := k.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (k *KccolCryptoWriter) encryptBySessionId(payload []byte, sessionId []byte, rand io.Reader) ([]byte, error) {
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

	// 3. 生成随机的 nonce（12字节）
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}
	record := make([]byte, 5)
	record[0] = byte(recordTypeApplicationData)

	n := len(payload) + 1 + aead.Overhead()
	vers := k.tlsVersion
	if vers == 0 {
		// Some TLS servers fail if the record version is
		// greater than TLS 1.0 for the initial ClientHello.
		vers = VersionTLS10
	} else if vers == VersionTLS13 {
		// TLS 1.3 froze the record layer version to 1.2.
		// See RFC 8446, Section 5.1.
		vers = VersionTLS12
	}
	record[1] = byte(vers >> 8)
	record[2] = byte(vers)
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	// 4. 使用 AES-GCM 加密数据，并提供 additionalData 作为附加数据
	ciphertext := aead.Seal(nonce, nonce, payload, nil)
	// Update length to include nonce, MAC and any block padding needed.
	n = len(ciphertext)
	record[3] = byte(n >> 8)
	record[4] = byte(n)
	return append(record[:recordHeaderLen], ciphertext...), nil
}
