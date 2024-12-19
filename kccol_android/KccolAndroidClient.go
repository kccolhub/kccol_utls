package kccol_android

import (
	tls "github.com/refraction-networking/utls"
	"io"
	"net"
	"time"
)

type KccolAndroidClient struct {
	client *tls.KccolGateWayClient
	io.ReadWriteCloser
}

func NewClient(severName string, addr string, userName string, password string) *KccolAndroidClient {
	client := tls.NewKccolGateWayClient(severName)
	err := client.Init(addr, userName, password)
	if err != nil {
		return nil
	}
	return &KccolAndroidClient{
		client: client,
	}
}

func (c *KccolAndroidClient) Write(p []byte) (int, error) {
	return c.client.Write(p)
}

func (c *KccolAndroidClient) Close() error {
	return c.client.Close()
}

func (c *KccolAndroidClient) Read(p []byte) (int, error) {
	return c.client.Read(p)
}

func (c *KccolAndroidClient) ReadFromNextUtil() ([]byte, error) {
	return c.client.ReadFromNextUtil()
}

func (c *KccolAndroidClient) LocalAddr() net.Addr {
	return c.client.LocalAddr()
}

func (c *KccolAndroidClient) RemoteAddr() net.Addr {
	return c.client.RemoteAddr()
}

func (c *KccolAndroidClient) SetDeadline(t time.Time) error {
	return c.client.SetDeadline(t)
}

func (c *KccolAndroidClient) SetReadDeadline(t time.Time) error {
	return c.client.SetReadDeadline(t)
}

func (c *KccolAndroidClient) SetWriteDeadline(t time.Time) error {
	return c.client.SetWriteDeadline(t)
}
