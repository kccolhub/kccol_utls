package utils

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

const inviteCodeLength = 8

type SessionId struct {
	RealTime   uint32
	InviteCode string //必须传8个字符串否则在转为bytes会自动填0,
	ClientCode [6]byte
}

// NewSessionId /**只能用该函数创建SessionId
func NewSessionId(realTime uint32, inviteCode string, clientCode [6]byte) *SessionId {
	return &SessionId{
		RealTime:   realTime,
		InviteCode: paddingInviteCode(inviteCode, inviteCodeLength),
		ClientCode: clientCode,
	}
}

// NewSessionId /**只能用该函数创建SessionId
func NewSessionIdWithDefaultClientCode(realTime uint32, inviteCode string) (*SessionId, error) {
	clientCode, err := GetMACAddressesBytes()
	if err != nil {
		return nil, err
	}
	return &SessionId{
		RealTime:   realTime,
		InviteCode: paddingInviteCode(inviteCode, inviteCodeLength),
		ClientCode: clientCode,
	}, nil
}

func NewSessionIdWithClientCode(realTime uint32, inviteCode string, clientCode [6]byte) (*SessionId, error) {
	return &SessionId{
		RealTime:   realTime,
		InviteCode: paddingInviteCode(inviteCode, inviteCodeLength),
		ClientCode: clientCode,
	}, nil
}

func paddingInviteCode(inviteCode string, length int) string {
	inviteCodeBytes := []byte(inviteCode)
	if len(inviteCodeBytes) > length {
		inviteCodeBytes = inviteCodeBytes[:length]
		return string(inviteCodeBytes)
	} else if len(inviteCodeBytes) == length {
		return inviteCode
	}
	paddedArray := make([]byte, length)
	startIndex := length - len(inviteCode)
	copy(paddedArray[startIndex:], inviteCode)
	return string(paddedArray)
}

func SessionId2Bytes(id SessionId) ([32]byte, error) {
	result := make([]byte, 32)
	inviteCode := []byte(id.InviteCode)
	copy(result[4:12], inviteCode[0:8])
	copy(result[14:20], id.ClientCode[0:6])
	// 定义数组长度
	length := 12
	randomBytes := make([]byte, length)
	// 生成随机字节
	_, err := rand.Read(randomBytes)
	if err != nil {
		fmt.Println("Error:", err)
		return [32]byte(result), err
	}
	AddFromEach32Bit(result, id.RealTime)
	copy(result[20:32], randomBytes[0:12])
	fakeTime := ^id.RealTime
	binary.BigEndian.PutUint32(result[0:4], fakeTime)
	return [32]byte(result), nil
}

func Bytes2SessionId(session []byte) (SessionId, error) {
	sessionTmp := make([]byte, 32)
	length := copy(sessionTmp, session)
	if length < 32 {
		return SessionId{}, errors.New("length <32  error")
	}
	fakeTime := InvertBytes(sessionTmp[0:4])
	realTime := binary.BigEndian.Uint32(fakeTime)
	SubtractFromEach32Bit(sessionTmp, realTime)
	inviteCode := sessionTmp[4:12]
	//versionCode := sessionTmp[12:14] do not need version now
	clientCode := sessionTmp[14:20]
	return SessionId{
		RealTime:   realTime,
		InviteCode: string(inviteCode),
		ClientCode: [6]byte(clientCode),
	}, nil
}
