package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func InvertBytes(data []byte) []byte {
	inverted := make([]byte, len(data))
	for i, b := range data {
		inverted[i] = ^b // 逐位取反
	}
	return inverted
}

func SubtractFromEach32Bit(data []byte, subValue uint32) {
	for i := 0; i < len(data); i += 4 {
		// 确保剩余的字节数足够形成一个16位整数
		if i+1 < len(data) {
			// 从两个字节形成一个16位整数
			value := binary.BigEndian.Uint32(data[i : i+4])

			// 进行减法操作
			value -= subValue

			// 将结果写回字节数组
			binary.BigEndian.PutUint32(data[i:i+4], value)
		}
	}
}

func StringTo6ByteHash(input string) ([6]byte, error) {
	// 使用 SHA-256 对字符串进行哈希
	hash := sha256.Sum256([]byte(input))

	// 获取哈希值的前 6 字节
	var result [6]byte
	copy(result[:], hash[:6])

	return [6]byte(result[:]), nil
}

func AddFromEach32Bit(data []byte, subValue uint32) {
	for i := 0; i < len(data); i += 4 {
		// 确保剩余的字节数足够形成一个16位整数
		if i+1 < len(data) {
			// 从两个字节形成一个16位整数
			value := binary.BigEndian.Uint32(data[i : i+4])

			// 进行加法操作
			value += subValue

			// 将结果写回字节数组
			binary.BigEndian.PutUint32(data[i:i+4], value)
		}
	}
}

func CheckTimeBeforeCurrentSeconds(timeStamp uint32, seconds int) bool {
	return timeStamp < uint32(time.Now().Unix()-int64(seconds))
}

func GetMACAddressesBytes() ([6]byte, error) {
	clientCodes, err := GetMACAddresses()
	if err != nil {
		return [6]byte{}, err
	}
	if len(clientCodes) <= 0 {
		return [6]byte{}, errors.New("has no client code")
	}
	clientCode, err := net.ParseMAC(clientCodes[0])
	if err != nil {
		return [6]byte{}, err
	}
	if len(clientCode) != 6 {
		return [6]byte{}, errors.New("invalid client code")
	}
	return [6]byte(clientCode), nil
}

func GetMACAddresses() ([]string, error) {
	var macAddresses []string
	// 获取所有网络接口
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// 遍历每个网络接口
	for _, iface := range interfaces {
		// 获取接口的硬件地址（MAC 地址）
		mac := iface.HardwareAddr.String()
		// 如果有 MAC 地址，则添加到结果列表
		if mac != "" {
			macAddresses = append(macAddresses, mac)
		}
	}

	return macAddresses, nil
}

func RandomInviteCode() (string, error) {
	// 随机生成字符串长度，范围为 0 到 20
	length, err := rand.Int(rand.Reader, big.NewInt(21))
	if err != nil {
		return "", err
	}

	// 创建一个 byte 切片，存储随机字符
	result := make([]byte, length.Int64())
	for i := range result {
		// 从 charset 中随机选择字符
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[index.Int64()]
	}

	return string(result), nil
}
