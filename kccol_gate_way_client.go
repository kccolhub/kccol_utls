package tls

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

type KccolGateWayClient struct {
	serverName   string
	socks5Client *Socks5Client
	tlsLayer     *KccolTLSLayer
	conn         *net.TCPConn
	rawInput     bytes.Buffer
	io.ReadWriteCloser
	net.Conn
}

func NewKccolGateWayClient(serverName string) *KccolGateWayClient {
	return &KccolGateWayClient{
		serverName: serverName,
	}
}

func (c *KccolGateWayClient) Init(addr string, userName string, password string) error {
	conn, err := net.Dial("tcp", c.serverName)
	if err != nil {
		return err
	}
	if conn == nil {
		return errors.New("nil connection")
	}
	tcpConn := conn.(*net.TCPConn)
	err = tcpConn.SetKeepAlive(true)
	if err != nil {
		return err
	}
	err = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	if err != nil {
		return err
	} // 每 30 秒发送一次 Keep-Alive

	c.conn = tcpConn
	c.tlsLayer = NewKccolTLSLayer()
	err = c.tlsLayer.Init(conn)
	if err != nil {
		return err
	}
	c.socks5Client, err = NewSocks5Client(userName, password, c.tlsLayer)
	if err != nil {
		return err
	}
	err = c.socks5Client.Init(addr)
	if err != nil {
		return err
	}

	return nil
}

func (c *KccolGateWayClient) topLayer() ITransferLayer {
	return c.tlsLayer
}

func (c *KccolGateWayClient) Write(p []byte) (int, error) {
	return c.socks5Client.Write(p)
}

func (c *KccolGateWayClient) Close() error {
	return c.conn.Close()
}

func (c *KccolGateWayClient) Read(p []byte) (int, error) {
	return c.socks5Client.Read(p)
}

func (c *KccolGateWayClient) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *KccolGateWayClient) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *KccolGateWayClient) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *KccolGateWayClient) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *KccolGateWayClient) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *KccolGateWayClient) ReadFromNextUtil() ([]byte, error) {
	result, err := c.topLayer().ReadFromNextUtil()
	return result[:], err
}

func (c *KccolGateWayClient) SetKeepAlive() error {
	err := c.conn.SetKeepAlive(true)
	if err != nil {
		return err
	}
	err = c.conn.SetKeepAlivePeriod(30 * time.Second)
	if err != nil {
		return err
	}
	return nil
}
