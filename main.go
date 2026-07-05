package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
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

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return fmt.Errorf("failed to marshal passwords: %v", err)
	}

	chiper, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(chiper)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %v", err)
	}

	encryptedData := gcm.Seal(nil, nonce, data, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(nonce)
	if err != nil {
		return fmt.Errorf("failed to write nonce to file: %v", err)
	}

	_, err = file.Write(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to write encrypted data to file: %v", err)
	}

	return nil
}

func (pm *PasswordManager) LoadFromFile() error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	file, err := os.Open(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	chiper, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(chiper)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())

	n, err := io.ReadFull(file, nonce)
	if err != nil {
		return fmt.Errorf("failed to read nonce from file: %v", err)
	}
	if n != len(nonce) {
		return fmt.Errorf("failed to read complete nonce from file")
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read data from file: %v", err)
	}

	decryptedData, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	err = json.Unmarshal(decryptedData, &pm.passwords)
	if err != nil {
		return fmt.Errorf("failed to unmarshal passwords: %v", err)
	}

	return nil
}

func (pm *PasswordManager) CheckPasswordStrength(password string) error {

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?/", char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")
	}

	return nil
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	var result []Password
	for _, pwd := range pm.passwords {
		if pwd.Category == category {
			result = append(result, pwd)
		}
	}
	return result
}
func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	searchMap := make(map[string][]string)

	for _, pwd := range pm.passwords {
		if _, exists := searchMap[pwd.Value]; !exists {
			searchMap[pwd.Value] = append(searchMap[pwd.Value], pwd.Name)
		} else {
			if !slices.Contains(searchMap[pwd.Value], pwd.Name) {
				searchMap[pwd.Value] = append(searchMap[pwd.Value], pwd.Name)
			}
		}
	}

	finalMap := make(map[string][]string)
	for value, names := range searchMap {
		if len(names) > 1 {
			finalMap[value] = names
		}
	}

	return finalMap
}

func (pm *PasswordManager) UpdatePassword(name string, newPassword string) error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	password, exists := pm.passwords[name]
	if !exists {
		return fmt.Errorf("password with name '%s' does not exist", name)
	}

	err := pm.CheckPasswordStrength(newPassword)
	if err != nil {
		return fmt.Errorf("new password does not meet strength requirements")
	}

	password.Value = newPassword
	password.LastModified = time.Now()
	pm.passwords[name] = password
	return nil
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
