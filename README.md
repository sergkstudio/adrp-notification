# Password Notifier

Это приложение предназначено для проверки даты последнего изменения пароля пользователей в Microsoft Active Directory (AD). Если пароль не менялся более 5 месяцев, пользователю будет отправлено уведомление на электронную почту.

## Установка

### Требования

- Python 3.9 или выше
- Docker
- Docker Compose

### Клонирование репозитория

```bash
git clone https://github.com/sergkstudio/adrp-notification.git
cd adrp-notification
```

### Настройка переменных окружения

Создайте файл `.env` в корневом каталоге проекта и заполните его следующими переменными:

```plaintext
AD_SERVER=your_server
AD_USER=your_DN
AD_PASSWORD=SecurePassword123
AD_BASE_DN=your_DN
AD_INCLUDED_OUS=your_OU

SMTP_SERVER=smtp.domain.example
SMTP_PORT=587
SMTP_USER=noreply@domain.example
SMTP_PASSWORD=EmailPassword123
SMTP_FROM_EMAIL=noreply@domain.example

EMAIL_DOMAIN=@domain.example
PASSWORD_AGE_DAYS=150  # 5 месяцев
CHECK_INTERVAL=3600
```

### Запуск приложения

Для сборки и запуска приложения используйте Docker Compose:

```bash
docker-compose up --build
```

## Описание работы приложения

1. Приложение устанавливает соединение с Microsoft Active Directory.
2. Оно проверяет дату последнего изменения пароля для всех пользователей в указанных OU (Organizational Units).
3. Если пароль не менялся более 5 месяцев, пользователю отправляется уведомление на электронную почту.
4. Приложение работает в бесконечном цикле, проверяя пользователей с заданным интервалом.

## Логирование

Логи приложения сохраняются в файл `password_notifier.log`. Вы можете просмотреть этот файл для диагностики и отслеживания работы приложения.

## Лицензия

Этот проект лицензирован под MIT License - смотрите файл [LICENSE](LICENSE) для подробностей.
