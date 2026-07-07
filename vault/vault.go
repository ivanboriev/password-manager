package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/ivanboriev/password-manager/passwordmanager"
)

type Vault struct {
	passwords     map[string]passwordmanager.Password
	masterKey     []byte
	filePath      string
	isInitialized bool
}

func New(filePath string) *Vault {
	return &Vault{
		passwords: make(map[string]passwordmanager.Password),
		filePath:  filePath,
	}
}

func (v *Vault) SetMasterKey(masterPassword string) error {
	if len(masterPassword) < 8 {
		return fmt.Errorf("master password must be at least 8 characters long")
	}

	buffer := make([]byte, 32)
	copy(buffer, []byte(masterPassword))
	v.masterKey = buffer
	v.isInitialized = true

	return nil
}

func (v *Vault) IsInitialized() bool {
	return v.isInitialized
}

func (v *Vault) Save(name, value, category string) error {
	if !v.isInitialized {
		return fmt.Errorf("vault is not initialized")
	}

	if _, exists := v.passwords[name]; exists {
		return fmt.Errorf("password with name '%s' already exists", name)
	}

	v.passwords[name] = passwordmanager.NewPassword(name, value, category)
	return nil
}

func (v *Vault) Get(name string) (passwordmanager.Password, error) {
	if !v.isInitialized {
		return passwordmanager.Password{}, fmt.Errorf("vault is not initialized")
	}

	password, exists := v.passwords[name]
	if !exists {
		return passwordmanager.Password{}, fmt.Errorf("password with name '%s' does not exist", name)
	}

	return password, nil
}

func (v *Vault) List() []passwordmanager.Password {
	passwords := make([]passwordmanager.Password, 0, len(v.passwords))
	for _, pwd := range v.passwords {
		passwords = append(passwords, pwd)
	}
	return passwords
}

func (v *Vault) Update(name, newValue string) error {
	if !v.isInitialized {
		return fmt.Errorf("vault is not initialized")
	}

	password, exists := v.passwords[name]
	if !exists {
		return fmt.Errorf("password with name '%s' does not exist", name)
	}

	password.Value = newValue
	password.LastModified = time.Now()
	v.passwords[name] = password
	return nil
}

func (v *Vault) Delete(name string) error {
	if !v.isInitialized {
		return fmt.Errorf("vault is not initialized")
	}

	if _, exists := v.passwords[name]; !exists {
		return fmt.Errorf("password with name '%s' does not exist", name)
	}

	delete(v.passwords, name)
	return nil
}

func (v *Vault) ListCategories() []string {
	categories := make(map[string]bool)
	for _, pwd := range v.passwords {
		categories[pwd.Category] = true
	}

	result := make([]string, 0, len(categories))
	for cat := range categories {
		result = append(result, cat)
	}

	slices.Sort(result)
	return result
}

func (v *Vault) GetByCategory(category string) []passwordmanager.Password {
	var result []passwordmanager.Password
	for _, pwd := range v.passwords {
		if pwd.Category == category {
			result = append(result, pwd)
		}
	}
	return result
}

func (v *Vault) FindDuplicates() map[string][]string {
	searchMap := make(map[string][]string)

	for _, pwd := range v.passwords {
		searchMap[pwd.Value] = append(searchMap[pwd.Value], pwd.Name)
	}

	finalMap := make(map[string][]string)
	for value, names := range searchMap {
		if len(names) > 1 {
			finalMap[value] = names
		}
	}

	return finalMap
}

func (v *Vault) Stats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["total"] = len(v.passwords)
	categories := make(map[string]int)
	for _, cat := range v.ListCategories() {
		categories[cat] = len(v.GetByCategory(cat))
	}
	stats["categories"] = categories

	passwordTimes := make([]time.Time, 0, len(v.passwords))
	for _, pwd := range v.passwords {
		passwordTimes = append(passwordTimes, pwd.CreatedAt)
	}

	slices.SortFunc(passwordTimes, func(a, b time.Time) int {
		if a.Before(b) {
			return -1
		}
		if b.Before(a) {
			return 1
		}
		return 0
	})

	if len(passwordTimes) > 0 {
		stats["oldest"] = passwordTimes[0]
		stats["newest"] = passwordTimes[len(passwordTimes)-1]
	} else {
		stats["oldest"] = nil
		stats["newest"] = nil
	}

	return stats
}

func (v *Vault) SaveToFile() error {
	if !v.isInitialized {
		return fmt.Errorf("vault is not initialized")
	}

	data, err := json.Marshal(v.passwords)
	if err != nil {
		return fmt.Errorf("failed to marshal passwords: %v", err)
	}

	encrypted, err := v.encrypt(data)
	if err != nil {
		return err
	}

	if err := os.WriteFile(v.filePath, encrypted, 0644); err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

func (v *Vault) LoadFromFile() error {
	if !v.isInitialized {
		return fmt.Errorf("vault is not initialized")
	}

	data, err := os.ReadFile(v.filePath)
	if err != nil {
		return err
	}

	decrypted, err := v.decrypt(data)
	if err != nil {
		return fmt.Errorf("failed to decrypt data: %v", err)
	}

	if err := json.Unmarshal(decrypted, &v.passwords); err != nil {
		return fmt.Errorf("failed to unmarshal passwords: %v", err)
	}

	return nil
}

func (v *Vault) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	encrypted := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, encrypted...), nil
}

func (v *Vault) decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}
