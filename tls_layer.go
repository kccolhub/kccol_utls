package tls

import (
	"bytes"
	"fmt"
	"github.com/refraction-networking/utls/utils"
	"io"
	"net"
	"time"
)

type KccolTLSLayer struct {
	conn              net.Conn
	tlsClient         *UConn
	lastLayer         ITransferLayer
	nextLayer         ITransferLayer
	handshakeFinished bool
	readerBuffer      bytes.Buffer
	io.ReadWriter
	ITransferLayer
	sessionId [32]byte
}

func NewKccolTLSLayer() *KccolTLSLayer {
	return &KccolTLSLayer{
		handshakeFinished: false,
		sessionId:         [32]byte{},
	}
}

func (kl *KccolTLSLayer) Init(conn net.Conn) error {
	kl.conn = conn
	kl.handshakeFinished = false
	err := kl.handshake()
	if err != nil {
		return err
	}
	return nil
}

func (kl *KccolTLSLayer) handshake() error {
	config := Config{
		ServerName:         "www.baidu.com",
		InsecureSkipVerify: true,
	}
	uTlsConn := UClient(kl.conn, &config, HelloCustom)
	kl.tlsClient = uTlsConn
	// do not use this particular spec in production
	// make sure to generate a separate copy of ClientHelloSpec for every connection
	spec := ClientHelloSpec{
		TLSVersMax: VersionTLS12,
		TLSVersMin: VersionTLS10,
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_AES_128_GCM_SHA256, // tls 1.3
			FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []byte{0}}, // uncompressed
			&SessionTicketExtension{},
			&ALPNExtension{AlpnProtocols: []string{"myFancyProtocol", "http/1.1"}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256,
				ECDSAWithP384AndSHA384,
				ECDSAWithP521AndSHA512,
				PSSWithSHA256,
				PSSWithSHA384,
				PSSWithSHA512,
				PKCS1WithSHA256,
				PKCS1WithSHA384,
				PKCS1WithSHA512,
				ECDSAWithSHA1,
				PKCS1WithSHA1}},
			&KeyShareExtension{[]KeyShare{
				{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: X25519},
			}},
			&PSKKeyExchangeModesExtension{[]uint8{1}}, // pskModeDHE
			&SupportedVersionsExtension{[]uint16{
				VersionTLS12,
				VersionTLS11,
				VersionTLS10}},
		},
		GetSessionID: nil,
	}
	err := uTlsConn.ApplyPreset(&spec)
	if err != nil {
		return err
	}
	sessionId, err := getSessionId()
	kl.sessionId = sessionId
	if err != nil {
		return fmt.Errorf("get session id error error: %+v", err)
	}
	uTlsConn.HandshakeState.Hello.SessionId = sessionId[:]
	err = uTlsConn.Handshake()
	if err != nil {
		return fmt.Errorf("uTlsConn.Handshake() error: %+v", err)
	}
	return nil
}

func (kl *KccolTLSLayer) Next() ITransferLayer {
	return nil
}

func (kl *KccolTLSLayer) SetNext(layer ITransferLayer) {

}

func (kl *KccolTLSLayer) Last() ITransferLayer {
	return kl.lastLayer
}

func (kl *KccolTLSLayer) SetLast(layer ITransferLayer) {
	kl.lastLayer = layer
}

func (kl *KccolTLSLayer) WriteToNext(p []byte) (int, error) {
	//下一层理论上是socket层,暂时和tls层耦合在一起，todo 将socket 独立一层
	return kl.tlsClient.writeApplicationDataRecordLockedCustom(p[:], kl.sessionId[:])
}
func (kl *KccolTLSLayer) ReadFromNextUtil() ([]byte, error) {
	result, err := kl.tlsClient.readRecordCustom(kl.sessionId[:])
	return result[:], err
}

func getSessionId() ([32]byte, error) {
	inviteCode, err := utils.RandomInviteCode()
	if err != nil {
		return [32]byte{}, err
	}

	//sessionId := po.NewSessionId(uint32(time.Now().Unix()), inviteCode, [6]byte{})
	sessionId, err := utils.NewSessionIdWithDefaultClientCode(uint32(time.Now().Unix()), inviteCode)
	if err != nil {
		return [32]byte{}, fmt.Errorf("po.NewSessionIdWithDefaultClientCode error: %+v", err)
	}
	result, err := utils.SessionId2Bytes(*sessionId)
	if err != nil {
		return [32]byte{}, fmt.Errorf("po.SessionId2Bytes error: %+v", err)
	}
	return result, nil
}

func (kl *KccolTLSLayer) Write(p []byte) (n int, err error) {
	return kl.WriteToNext(p)
}

func (kl *KccolTLSLayer) Read(p []byte) (n int, err error) {
	if kl.readerBuffer.Len() > 0 {
		return kl.readerBuffer.Read(p)
	}
	nextRead, err := kl.ReadFromNextUtil()
	kl.readerBuffer.Write(nextRead)
	return kl.readerBuffer.Read(p)
}
