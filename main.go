package main

import (
	"fmt"
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
	passwords     map[string]Password
	masterKey     []byte `json:"-"`
	filePath      string `json:"-"`
	isInitialized bool   `json:"-"`
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

func main() {

	pm := NewPasswordManager("passwords.dat")

	fmt.Printf("Initialized: %t\n", pm.isInitialized)
	fmt.Printf("File path: %s\n", pm.filePath)
	fmt.Printf("Passwords count: %d\n", len(pm.passwords))
}
