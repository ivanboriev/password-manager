package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
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
		return err
	}

	password.Value = newPassword
	password.LastModified = time.Now()
	pm.passwords[name] = password
	return nil
}

func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	if _, exists := pm.passwords[name]; !exists {
		return fmt.Errorf("password with name '%s' does not exist", name)
	}

	delete(pm.passwords, name)
	return nil
}

func (pm *PasswordManager) ListCategories() []string {
	categories := make(map[string]bool)
	for _, pwd := range pm.passwords {
		categories[pwd.Category] = true
	}
	result := make([]string, 0, len(categories))
	for cat := range categories {
		result = append(result, cat)
	}

	slices.Sort(result)

	return result
}

func (pm *PasswordManager) GetPasswordStats() map[string]interface{} {
	stats := make(map[string]interface{})

	stats["total"] = len(pm.passwords)
	categories := make(map[string]int)
	for _, cat := range pm.ListCategories() {
		categories[cat] = len(pm.GetPasswordsByCategory(cat))
	}
	stats["categories"] = categories

	passwordTimes := make([]time.Time, 0, len(pm.passwords))
	for _, pwd := range pm.passwords {
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

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}
func showSuccess(message string) {
	fmt.Printf("%s%s%s\n", colorGreen, message, colorReset)
}
func showError(message string) {
	fmt.Printf("%s%s%s\n", colorRed, message, colorReset)
}
func showInfo(message string) {
	fmt.Printf("%s%s%s\n", colorYellow, message, colorReset)
}
func waitForEnter() {
	fmt.Println("Press Enter to continue...")
	stdin := bufio.NewReader(os.Stdin)
	stdin.ReadString('\n')
}

func ReadUserInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading user input: %v\n", err)
		os.Exit(1)
	}

	return strings.TrimSpace(input)
}

func readPassword() (string, error) {
	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(bytePassword), nil
}
func ShowMainMenu() {
	clearScreen()
	fmt.Println("=======================================")
	fmt.Println("          Password Manager")
	fmt.Println("=======================================")
	fmt.Println("1. Generate new password")
	fmt.Println("2. Add new password")
	fmt.Println("3. Get password")
	fmt.Println("4. List all passwords")
	fmt.Println("5. Update password")
	fmt.Println("6. Delete password")
	fmt.Println("7. List categories")
	fmt.Println("8. Show password statistics")
	fmt.Println("9. Find duplicate passwords")
	fmt.Println("0. Exit")
	fmt.Println("=======================================")
}

func PrintPasswordList(passwords []Password) {
	fmt.Println("=== Password list ===")
	fmt.Println("Name          Category       Created           Last Modified")
	fmt.Println("---------------------------------------------------------------")
	for _, pwd := range passwords {
		fmt.Printf("%-13s %-14s %-17s %-17s\n", pwd.Name, pwd.Category, pwd.CreatedAt.Format("2006-01-02 15:04:05"), pwd.LastModified.Format("2006-01-02 15:04:05"))
	}

}

func ShowPasswordDetails(password Password) {
	fmt.Println("=== Password details ===")
	fmt.Printf("Service: %s\n", password.Name)
	fmt.Printf("Category: %s\n", password.Category)
	fmt.Printf("Password: %s\n", password.Value)
	fmt.Printf("Created: %s\n", password.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Modified: %s\n", password.LastModified.Format("2006-01-02 15:04:05"))
}

func HandlePasswordGeneration(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Password Generation ===")
	lengthInput := ReadUserInput("Enter password length (min 8): ")
	var length int
	_, err := fmt.Sscanf(lengthInput, "%d", &length)
	if err != nil || length < 8 {
		showError("invalid length input")
		waitForEnter()
		return err
	}

	password, err := pm.GeneratePassword(length)
	if err != nil {
		showError("Generation failed: " + err.Error())
		waitForEnter()
		return err
	}

	showSuccess("Password generated successfully!")
	fmt.Printf("Generated password: %s\n", password)
	waitForEnter()

	return nil
}

func HandlePasswordAdd(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Add New Password ===")
	name := ReadUserInput("Enter service name: ")
	category := ReadUserInput("Enter category: ")

	value := ReadUserInput("Enter password (or press Enter to generate):")
	if len(value) == 0 {
		password, err := pm.GeneratePassword(8)
		if err != nil {
			showError("failed to generate password: " + err.Error())
			waitForEnter()
			return err
		}

		value = password
		showInfo("Generated password: " + value)
	} else {
		err := pm.CheckPasswordStrength(value)
		if err != nil {
			showError("failed to check password strength: " + err.Error())
			waitForEnter()
			return err
		}
	}

	err := pm.SavePassword(name, value, category)
	if err != nil {
		showError("failed to save password: " + err.Error())
		waitForEnter()
		return err
	}

	showSuccess("Password added successfully!")
	waitForEnter()
	return nil
}

func HandlePasswordSearch(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Search Password ===")
	name := ReadUserInput("Enter service name to search: ")

	password, err := pm.GetPassword(name)
	if err != nil {
		showError(fmt.Sprintf("Password not found: %v", err))
		waitForEnter()
		return err
	}
	showSuccess("Password found successfully!")
	ShowPasswordDetails(password)

	waitForEnter()
	return nil
}

func HandlePasswordList(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== List All Passwords ===")
	passwords := pm.ListPasswords()
	if len(passwords) == 0 {
		showInfo("No passwords found.")
	} else {
		PrintPasswordList(passwords)
	}
	waitForEnter()
	return nil
}

func HandlePasswordUpdate(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Update Password ===")
	name := ReadUserInput("Enter service name to update: ")
	newPassword, err := readPassword()
	if err != nil {
		showError("failed to read new password: " + err.Error())
		waitForEnter()
		return err
	}

	err = pm.UpdatePassword(name, newPassword)
	if err != nil {
		showError("failed to update password: " + err.Error())
		waitForEnter()
		return err
	}

	showSuccess("Password updated successfully!")
	waitForEnter()
	return nil
}

func HandleExitAndSave(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Saving and Exiting ===")
	fmt.Println("Saving changes...")
	err := pm.SaveToFile()
	if err != nil {
		return fmt.Errorf("error saving data: %v", err)
	}
	showSuccess("Passwords saved successfully!")
	showSuccess("Goodbye!")
	return nil
}

func HandleDeletePassword(pm *PasswordManager) error {
	clearScreen()
	name := ReadUserInput("Enter service name to delete: ")
	err := pm.DeletePassword(name)
	if err != nil {
		showError("failed to delete password: " + err.Error())
		waitForEnter()
	}
	showSuccess("Password deleted successfully!")
	waitForEnter()
	return nil
}

func HandleListCategories(pm *PasswordManager) error {
	clearScreen()
	categories := pm.ListCategories()
	fmt.Println("=== Categories ===")
	for _, cat := range categories {
		fmt.Println(cat)
	}
	waitForEnter()
	return nil
}

func HandleShowPasswordStatistics(pm *PasswordManager) error {
	clearScreen()
	stats := pm.GetPasswordStats()
	fmt.Println("=== Password Statistics ===")
	fmt.Printf("Total passwords: %d\n", stats["total"])
	fmt.Println("Passwords by category:")
	for cat, count := range stats["categories"].(map[string]int) {
		fmt.Printf("  %s: %d\n", cat, count)
	}
	if stats["oldest"] != nil {
		fmt.Printf("Oldest password created at: %s\n", stats["oldest"].(time.Time).Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("No passwords available.")
	}
	if stats["newest"] != nil {
		fmt.Printf("Newest password created at: %s\n", stats["newest"].(time.Time).Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("No passwords available.")
	}
	waitForEnter()
	return nil
}

func HandleShowDuplicates(pm *PasswordManager) error {
	clearScreen()
	duplicates := pm.FindDuplicatePasswords()
	if len(duplicates) == 0 {
		showInfo("No duplicate passwords found.")
	} else {
		fmt.Println("=== Duplicate Passwords ===")
		for value, names := range duplicates {
			fmt.Printf("Password: %s\n", value)
			fmt.Printf("Used by services: %s\n", strings.Join(names, ", "))
			fmt.Println("---------------------------")
		}
	}
	waitForEnter()
	return nil
}

func main() {
	showInfo("Welcome to the Password Manager!")
	showInfo("=== Password Manager Initialization ===")

	pm := NewPasswordManager("passwords.dat")

	password, err := readPassword()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	err = pm.SetMasterPassword(password)
	if err != nil {
		fmt.Printf("Error setting master password: %v\n", err)
		os.Exit(1)
	}

	err = pm.LoadFromFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			showInfo("No existing password data found. Starting fresh.")
		} else {
			fmt.Printf("Error loading password data: %v\n", err)
			os.Exit(1)
		}
	}

	showSuccess("Password manager initialized successfully!")

	waitForEnter()

	for {
		ShowMainMenu()

		key := ReadUserInput("Enter your choice: ")

		switch key {
		case "1":
			HandlePasswordGeneration(pm)
		case "2":
			HandlePasswordAdd(pm)
		case "3":
			HandlePasswordSearch(pm)
		case "4":
			HandlePasswordList(pm)
		case "5":
			HandlePasswordUpdate(pm)
		case "6":
			HandleDeletePassword(pm)
		case "7":
			HandleListCategories(pm)
		case "8":
			HandleShowPasswordStatistics(pm)
		case "9":
			HandleShowDuplicates(pm)
		case "0":
			err := HandleExitAndSave(pm)
			if err != nil {
				showError("failed to save data: " + err.Error())
				os.Exit(1)
			}
			return
		default:
			showError("invalid option selected")
			waitForEnter()
		}
	}
}
