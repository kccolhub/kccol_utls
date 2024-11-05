package tls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"testing"
)

func TestNewKccolGateWayClient(t *testing.T) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				kccol := NewKccolGateWayClient("127.0.0.1:8080")
				return kccol, kccol.Init(addr, "test", "test")
			},
		},
	}

	res, err := httpClient.Get("https://ifconfig.co")
	if err != nil {
		log.Println(err)
		return
	}
	defer res.Body.Close()
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("tcp", string(b))

}

func encryptAESGCM(plaintext, additionalData []byte, key []byte) ([]byte, error) {
	// 1. 创建 AES 块加密器
	block, err := aes.NewCipher(key)
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
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// 4. 使用 AES-GCM 加密数据，并提供 additionalData 作为附加数据
	ciphertext := aead.Seal(nonce, nonce, plaintext, additionalData)

	return ciphertext, nil
}

func decryptAESGCM(ciphertext, additionalData, key []byte) ([]byte, error) {
	// 1. 创建 AES 块加密器
	block, err := aes.NewCipher(key)
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
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

func Test_main(t *testing.T) {
	// 示例密钥（32字节，适用于 AES-256）
	key := []byte("thisisaverysecretkey123678901234")

	// 待加密数据
	plaintext := []byte("Hello, AEAD AES-GCM Encryption!")

	// 附加数据
	additionalData := []byte("Metadata: User Info, Timestamp, etc.")

	// 加密
	ciphertext, err := encryptAESGCM(plaintext, additionalData, key)
	if err != nil {
		log.Fatal("Error encrypting:", err)
	}

	// 输出加密后的密文
	fmt.Printf("Ciphertext (hex): %x\n", ciphertext)

	// 解密
	decrypted, err := decryptAESGCM(ciphertext, additionalData, key)
	if err != nil {
		log.Fatal("Error decrypting:", err)
	}

	// 输出解密后的明文
	fmt.Printf("Decrypted text: %s\n", decrypted)
}
