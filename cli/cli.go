package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ivanboriev/password-manager/passwordmanager"
	"github.com/ivanboriev/password-manager/vault"
	"golang.org/x/term"
)

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

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
	bufio.NewReader(os.Stdin).ReadString('\n')
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

func PrintPasswordList(passwords []passwordmanager.Password) {
	fmt.Println("=== Password list ===")
	fmt.Println("Name          Category       Created           Last Modified")
	fmt.Println("---------------------------------------------------------------")
	for _, pwd := range passwords {
		fmt.Printf("%-13s %-14s %-17s %-17s\n",
			pwd.Name, pwd.Category,
			pwd.CreatedAt.Format("2006-01-02 15:04:05"),
			pwd.LastModified.Format("2006-01-02 15:04:05"))
	}
}

func ShowPasswordDetails(password passwordmanager.Password) {
	fmt.Println("=== Password details ===")
	fmt.Printf("Service: %s\n", password.Name)
	fmt.Printf("Category: %s\n", password.Category)
	fmt.Printf("Password: %s\n", password.Value)
	fmt.Printf("Created: %s\n", password.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Last Modified: %s\n", password.LastModified.Format("2006-01-02 15:04:05"))
}

func HandlePasswordGeneration(v *vault.Vault) error {
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

	password, err := passwordmanager.GeneratePassword(length)
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

func HandlePasswordAdd(v *vault.Vault) error {
	clearScreen()
	fmt.Println("=== Add New Password ===")
	name := ReadUserInput("Enter service name: ")
	category := ReadUserInput("Enter category: ")

	value := ReadUserInput("Enter password (or press Enter to generate):")
	if len(value) == 0 {
		password, err := passwordmanager.GeneratePassword(8)
		if err != nil {
			showError("failed to generate password: " + err.Error())
			waitForEnter()
			return err
		}

		value = password
		showInfo("Generated password: " + value)
	} else {
		if err := passwordmanager.CheckPasswordStrength(value); err != nil {
			showError("failed to check password strength: " + err.Error())
			waitForEnter()
			return err
		}
	}

	if err := v.Save(name, value, category); err != nil {
		showError("failed to save password: " + err.Error())
		waitForEnter()
		return err
	}

	showSuccess("Password added successfully!")
	waitForEnter()
	return nil
}

func HandlePasswordSearch(v *vault.Vault) error {
	clearScreen()
	fmt.Println("=== Search Password ===")
	name := ReadUserInput("Enter service name to search: ")

	password, err := v.Get(name)
	if err != nil {
		showError("Password not found: " + err.Error())
		waitForEnter()
		return err
	}

	showSuccess("Password found successfully!")
	ShowPasswordDetails(password)
	waitForEnter()
	return nil
}

func HandlePasswordList(v *vault.Vault) error {
	clearScreen()
	fmt.Println("=== List All Passwords ===")
	passwords := v.List()
	if len(passwords) == 0 {
		showInfo("No passwords found.")
	} else {
		PrintPasswordList(passwords)
	}
	waitForEnter()
	return nil
}

func HandlePasswordUpdate(v *vault.Vault) error {
	clearScreen()
	fmt.Println("=== Update Password ===")
	name := ReadUserInput("Enter service name to update: ")
	newPassword, err := readPassword()
	if err != nil {
		showError("failed to read new password: " + err.Error())
		waitForEnter()
		return err
	}

	if err := passwordmanager.CheckPasswordStrength(newPassword); err != nil {
		showError("failed to check password strength: " + err.Error())
		waitForEnter()
		return err
	}

	if err := v.Update(name, newPassword); err != nil {
		showError("failed to update password: " + err.Error())
		waitForEnter()
		return err
	}

	showSuccess("Password updated successfully!")
	waitForEnter()
	return nil
}

func HandleDeletePassword(v *vault.Vault) error {
	clearScreen()
	name := ReadUserInput("Enter service name to delete: ")
	if err := v.Delete(name); err != nil {
		showError("failed to delete password: " + err.Error())
		waitForEnter()
		return err
	}
	showSuccess("Password deleted successfully!")
	waitForEnter()
	return nil
}

func HandleListCategories(v *vault.Vault) error {
	clearScreen()
	categories := v.ListCategories()
	fmt.Println("=== Categories ===")
	for _, cat := range categories {
		fmt.Println(cat)
	}
	waitForEnter()
	return nil
}

func HandleShowPasswordStatistics(v *vault.Vault) error {
	clearScreen()
	stats := v.Stats()
	fmt.Println("=== Password Statistics ===")
	fmt.Printf("Total passwords: %d\n", stats["total"])
	fmt.Println("Passwords by category:")
	for cat, count := range stats["categories"].(map[string]int) {
		fmt.Printf("  %s: %d\n", cat, count)
	}
	if stats["oldest"] != nil {
		fmt.Printf("Oldest password created at: %s\n",
			stats["oldest"].(time.Time).Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("No passwords available.")
	}
	if stats["newest"] != nil {
		fmt.Printf("Newest password created at: %s\n",
			stats["newest"].(time.Time).Format("2006-01-02 15:04:05"))
	} else {
		fmt.Println("No passwords available.")
	}
	waitForEnter()
	return nil
}

func HandleShowDuplicates(v *vault.Vault) error {
	clearScreen()
	duplicates := v.FindDuplicates()
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

func HandleExitAndSave(v *vault.Vault) error {
	clearScreen()
	fmt.Println("=== Saving and Exiting ===")
	fmt.Println("Saving changes...")
	if err := v.SaveToFile(); err != nil {
		return fmt.Errorf("error saving data: %v", err)
	}
	showSuccess("Passwords saved successfully!")
	showSuccess("Goodbye!")
	return nil
}

func Run() {
	showInfo("Welcome to the Password Manager!")
	showInfo("=== Password Manager Initialization ===")

	v := vault.New("passwords.dat")

	masterPassword, err := readPassword()
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}

	if err := v.SetMasterKey(masterPassword); err != nil {
		fmt.Printf("Error setting master password: %v\n", err)
		os.Exit(1)
	}

	if err := v.LoadFromFile(); err != nil {
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
			HandlePasswordGeneration(v)
		case "2":
			HandlePasswordAdd(v)
		case "3":
			HandlePasswordSearch(v)
		case "4":
			HandlePasswordList(v)
		case "5":
			HandlePasswordUpdate(v)
		case "6":
			HandleDeletePassword(v)
		case "7":
			HandleListCategories(v)
		case "8":
			HandleShowPasswordStatistics(v)
		case "9":
			HandleShowDuplicates(v)
		case "0":
			if err := HandleExitAndSave(v); err != nil {
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
