package utils

import (
	"fmt"
	"testing"
	"time"
)

func TestUtil(t *testing.T) {
	fmt.Printf("Original: %X\n", InvertBytes([]byte{0x01}))
	bytes := []byte{0x00, 0x01, 0x00, 0x02, 0x01, 0x03, 0x01, 0x03}
	currentTime := time.Now().Unix()
	fmt.Printf("SubtractFromEach32Bit Original: %X\n", bytes)
	SubtractFromEach32Bit(bytes, uint32(currentTime))
	fmt.Printf("SubtractFromEach32Bit End: %X\n", bytes)
	AddFromEach32Bit(bytes, uint32(currentTime))
	fmt.Printf("AddFromEach32Bit End: %X\n", bytes)
	fmt.Printf("currentTime End: %b\n", time.Now().Unix())
}
