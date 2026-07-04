package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"time"
)

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"createdAt"`
	LastModified time.Time `json:"lastModified"`
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		masterKey:     nil,
		filePath:      filePath,
		isInitialized: false,
	}
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {

	if len(masterPassword) < 8 {
		return fmt.Errorf("master password must be at least 8 characters long")
	}

	buffer := make([]byte, 32)

	copy(buffer, []byte(masterPassword))

	pm.masterKey = buffer

	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	if _, exists := pm.passwords[name]; exists {
		return fmt.Errorf("password with name '%s' already exists", name)
	}

	password := NewPassword(name, value, category)
	pm.passwords[name] = password

	return nil
}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, fmt.Errorf("password manager is not initialized")
	}

	password, exists := pm.passwords[name]
	if !exists {
		return Password{}, fmt.Errorf("password with name '%s' does not exist", name)
	}

	return password, nil
}
func (pm *PasswordManager) ListPasswords() []Password {

	passwords := make([]Password, 0, len(pm.passwords))

	for _, password := range pm.passwords {
		passwords = append(passwords, password)
	}

	return passwords

}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
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

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <master_password>")
		os.Exit(1)
	}

	pm := NewPasswordManager("passwords.dat")

	err := pm.SetMasterPassword(os.Args[1])

	if err != nil {
		fmt.Printf("Error setting master password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Initialized: %t\n", pm.isInitialized)
	fmt.Printf("File path: %s\n", pm.filePath)
	fmt.Printf("Passwords count: %d\n", len(pm.passwords))
}
