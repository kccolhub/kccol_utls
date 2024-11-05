package utils

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestSessionId(t *testing.T) {

	clientCode := make([]byte, 8)

	// 生成随机clientCode
	_, err := rand.Read(clientCode)
	if err != nil {
		fmt.Println("Error:", err)
		t.Error("generate random bytes fail")
	}
	inviteCode, err := RandomInviteCode()
	if err != nil {
		fmt.Println("Error:", err)
	}
	sessionId, err := NewSessionIdWithDefaultClientCode(uint32(time.Now().Unix()), inviteCode)
	if err != nil {
		fmt.Println("Error:", err)
		t.Error("generate new session id fail")
	}
	fmt.Println(sessionId)

	sessionBytes, err := SessionId2Bytes(*sessionId)
	if err != nil {
		t.Error("convert sessionId to bytes fail")
	}
	fmt.Printf("Original: %X\n", sessionBytes)
	nextSessionId, err := Bytes2SessionId(sessionBytes[0:32])
	if err != nil {
		t.Error("convert bytes to sessionId fail")
	}
	fmt.Println(nextSessionId)
	if *sessionId != nextSessionId {
		t.Error("test sessionId fail")
	}
}

func TestSessionIdTimes(t *testing.T) {
	times := 100
	for i := 0; i < times; i++ {
		TestSessionId(t)
	}
}
