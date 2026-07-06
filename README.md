# Password Manager

![Go 1.26](https://img.releaserun.com/badge/v/go/1.26.1.svg) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Утилита для локального безопасного хранения паролей. Все данные шифруются алгоритмом **AES-256-GCM** и сохраняются в файл `passwords.dat`.

![PasswordManager](art/pm.png)

---

## Функциональность

- **Генерация паролей** — создание криптостойких паролей заданной длины (от 8 символов) с использованием `crypto/rand`
- **Добавление пароля** — сохранение пары «сервис → пароль» с указанием категории
- **Просмотр пароля** — поиск по имени сервиса и отображение всех деталей
- **Список всех паролей** — таблица с именем, категорией, датами создания и изменения
- **Обновление пароля** — замена существующего пароля с проверкой сложности
- **Удаление пароля** — удаление записи по имени сервиса
- **Категории** — просмотр всех используемых категорий
- **Статистика** — общее количество паролей, распределение по категориям, самая старая и новая запись
- **Поиск дубликатов** — обнаружение одинаковых паролей, используемых в разных сервисах
- **Шифрование** — весь vault шифруется AES-256-GCM, данные хранятся в файле `passwords.dat`

---

## Требования к системе

- **Go** версии 1.26 или выше
- **ОС** — Linux, macOS, Windows (поддерживается `golang.org/x/term`)

---

## Установка

```bash
# Клонирование репозитория
git clone https://github.com/iboriev/password-manager.git
cd password-manager

# Сборка
go build -o pm .

# Запуск
./pm
```

Или запуск без сборки:

```bash
go run main.go
```

---

## Примеры использования

### Как CLI-утилита

При запуске утилита запрашивает мастер-пароль (минимум 8 символов) и показывает интерактивное меню:

```
=======================================
          Password Manager
=======================================
1. Generate new password
2. Add new password
3. Get password
4. List all passwords
5. Update password
6. Delete password
7. List categories
8. Show password statistics
9. Find duplicate passwords
0. Exit
=======================================
Enter your choice:
```

### Как Go-библиотека

```go
package main

import (
	"fmt"
	"log"
	"password-manager"
)

func main() {
	pm := NewPasswordManager("passwords.dat")

	// Установка мастер-пароля (минимум 8 символов)
	if err := pm.SetMasterPassword("my-secure-master-key"); err != nil {
		log.Fatal(err)
	}

	// Генерация пароля
	pwd, _ := pm.GeneratePassword(16)
	fmt.Println("Generated:", pwd)

	// Добавление пароля
	pm.SavePassword("github", pwd, "dev")

	// Получение пароля
	entry, _ := pm.GetPassword("github")
	fmt.Printf("Service: %s, Password: %s\n", entry.Name, entry.Value)

	// Список всех паролей
	for _, p := range pm.ListPasswords() {
		fmt.Println(p.Name, p.Category)
	}

	// Сохранение в зашифрованный файл
	pm.SaveToFile()
}
```

---

## Структура проекта

```
password-manager/
├── art/
│   └── pm.png               # Скриншот интерфейса
├── .gitignore                # Игнорирование passwords.dat
├── go.mod                    # Go-модуль (go 1.26)
├── go.sum                    # Контрольные суммы зависимостей
├── main.go                   # Исходный код (719 строк)
└── README.md                 # Документация
```

Весь код находится в одном файле `main.go`.

---

## Планы по развитию

- [ ] Key Derivation Function (Argon2/PBKDF2) для мастер-пароля
- [ ] Поддержка TOTP (одноразовые коды)
- [ ] Импорт/экспорт паролей (CSV, JSON)
- [ ] Графический интерфейс (TUI или веб-версия)
- [ ] Двухфакторная аутентификация для доступа к vault
- [ ] Модульная архитектура (разделение на пакеты)
- [ ] Юнит-тесты
- [ ] CI/CD (GitHub Actions)

---

## Лицензия

Проект распространяется под лицензией MIT. Подробнее — в файле [LICENSE](LICENSE).
