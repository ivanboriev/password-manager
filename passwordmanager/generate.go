package passwordmanager

import (
	"crypto/rand"
	"fmt"
)

func GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("password length must be at least 8 characters")
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"

	buffer := make([]byte, length)

	_, err := rand.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to generate random password: %v", err)
	}

	password := make([]byte, length)

	for i, val := range buffer {
		password[i] = charset[int(val)%len(charset)]
	}

	return string(password), nil
}
