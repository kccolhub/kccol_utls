package tls

import (
	"errors"
	"log"
	"net"
)

// Client is socks5 client wrapper
type Socks5Client struct {
	UserName string
	Password string
	tlsLayer *KccolTLSLayer
}

// This is just create a client, you need to use Dial to create conn
func NewSocks5Client(username, password string, tlsLayer *KccolTLSLayer) (*Socks5Client, error) {
	c := &Socks5Client{
		UserName: username,
		Password: password,
		tlsLayer: tlsLayer,
	}
	return c, nil
}

func (c *Socks5Client) Read(b []byte) (int, error) {
	return c.tlsLayer.Read(b)
}

func (c *Socks5Client) Write(b []byte) (int, error) {
	return c.tlsLayer.Write(b)
}

func (c *Socks5Client) InitWithDomain(domain string) error {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		_, err := c.Init(ip + ":443")
		if err != nil {
			continue
		}
		log.Print(ip)
		return nil
	}
	return errors.New("failed to init client")
}

func (c *Socks5Client) Init(dst string) (*Reply, error) {
	err := c.negotiate()
	if err != nil {
		return nil, err
	}
	a, h, p, err := ParseAddress(dst)
	if err != nil {
		return nil, err
	}
	if a == ATYPDomain {
		h = h[1:]
	}
	rp, err := c.Request(NewRequest(CmdConnect, a, h, p))
	if err != nil {
		return nil, err
	}
	return rp, nil
}

func (c *Socks5Client) InitUDP(dst string) (*Reply, error) {
	err := c.negotiate()
	if err != nil {
		return nil, err
	}
	a, h, p, err := ParseAddress(dst)
	if err != nil {
		return nil, err
	}
	if a == ATYPDomain {
		h = h[1:]
	}
	rp, err := c.Request(NewRequest(CmdUDP, a, h, p))
	if err != nil {
		return nil, err
	}
	return rp, nil
}

func (c *Socks5Client) negotiate() error {
	var err error
	m := MethodNone
	if c.UserName != "" && c.Password != "" {
		m = MethodUsernamePassword
	}
	rq := NewNegotiationRequest([]byte{m})
	if _, err := rq.WriteTo(c.tlsLayer); err != nil {
		return err
	}
	rp, err := NewNegotiationReplyFrom(c.tlsLayer)
	if err != nil {
		return err
	}
	if rp.Method != m {
		return errors.New("Unsupport method")
	}
	if m == MethodUsernamePassword {
		urq := NewUserPassNegotiationRequest([]byte(c.UserName), []byte(c.Password))
		if _, err := urq.WriteTo(c.tlsLayer); err != nil {
			return err
		}
		urp, err := NewUserPassNegotiationReplyFrom(c.tlsLayer)
		if err != nil {
			return err
		}
		if urp.Status != UserPassStatusSuccess {
			return ErrUserPassAuth
		}
	}
	return nil
}

func (c *Socks5Client) Request(r *Request) (*Reply, error) {
	if _, err := r.WriteTo(c.tlsLayer); err != nil {
		return nil, err
	}
	rp, err := NewReplyFrom(c.tlsLayer)
	if err != nil {
		return nil, err
	}
	if rp.Rep != RepSuccess {
		return nil, errors.New("Host unreachable")
	}
	return rp, nil
}
