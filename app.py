import os
from ldap3 import Server, Connection, ALL
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate
import logging
import time
from dotenv import load_dotenv
import sys

# Загрузка переменных окружения из .env файла
logging.info("Загрузка переменных окружения...")
load_dotenv()
logging.info("Переменные окружения успешно загружены")

# Конфигурационные параметры
AD_CONFIG = {
    'server': os.getenv('AD_SERVER'),
    'user': os.getenv('AD_USER'),
    'password': os.getenv('AD_PASSWORD'),
    'base_dn': os.getenv('AD_BASE_DN'),
    'included_ous': os.getenv('AD_INCLUDED_OUS').split(',')
}

SMTP_CONFIG = {
    'server': os.getenv('SMTP_SERVER'),
    'port': int(os.getenv('SMTP_PORT')),
    'user': os.getenv('SMTP_USER'),
    'password': os.getenv('SMTP_PASSWORD'),
    'from_email': os.getenv('SMTP_FROM_EMAIL')
}

EMAIL_DOMAIN = os.getenv('EMAIL_DOMAIN')
PASSWORD_AGE_DAYS = int(os.getenv('PASSWORD_AGE_DAYS'))
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL'))

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logging.info("Логирование настроено")

def convert_filetime(ft):
    """Конвертирует Windows FileTime в datetime"""
    try:
        result = datetime(1601, 1, 1) + timedelta(microseconds=ft//10)
        logging.debug(f"Конвертация FileTime {ft} в datetime: {result}")
        return result
    except Exception as e:
        logging.error(f"Ошибка при конвертации FileTime: {str(e)}")
        raise

def get_ad_connection():
    """Устанавливает соединение с AD"""
    try:
        logging.info(f"Попытка подключения к AD серверу: {AD_CONFIG['server']}")
        server = Server(AD_CONFIG['server'], get_info=ALL)
        conn = Connection(
            server,
            user=AD_CONFIG['user'],
            password=AD_CONFIG['password'],
            auto_bind=True
        )
        logging.info("Успешное подключение к AD")
        return conn
    except Exception as e:
        logging.error(f"Ошибка при подключении к AD: {str(e)}")
        raise

def get_users_with_old_passwords():
    """Возвращает пользователей с паролями старше заданного срока"""
    logging.info("Начало поиска пользователей с устаревшими паролями")
    conn = get_ad_connection()
    ou_filter = '(|{})'.format(''.join([f'(distinguishedName={ou})' for ou in AD_CONFIG['included_ous']]))
    
    search_filter = (
        '(&(objectCategory=person)(objectClass=user)'
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        f'{ou_filter})'
    )
    
    attributes = ['sAMAccountName', 'mail', 'pwdLastSet', 'distinguishedName']
    
    logging.info(f"Выполнение поиска в AD с фильтром: {search_filter}")
    conn.search(AD_CONFIG['base_dn'], search_filter, attributes=attributes)
    users = []
    
    for entry in conn.entries:
        try:
            pwd_last_set = convert_filetime(entry.pwdLastSet.value)
            delta = datetime.now() - pwd_last_set
            
            if delta.days >= PASSWORD_AGE_DAYS:
                user_info = {
                    'login': entry.sAMAccountName.value,
                    'email': entry.mail.value or f"{entry.sAMAccountName.value}{EMAIL_DOMAIN}",
                    'last_changed': pwd_last_set
                }
                users.append(user_info)
                logging.info(f"Найден пользователь с устаревшим паролем: {user_info['login']}, последняя смена: {user_info['last_changed']}")
        except Exception as e:
            logging.error(f"Ошибка при обработке пользователя {entry.sAMAccountName}: {str(e)}")
    
    conn.unbind()
    logging.info(f"Поиск завершен. Найдено пользователей с устаревшими паролями: {len(users)}")
    return users

def send_notification(email, login):
    """Отправляет email-уведомление"""
    logging.info(f"Подготовка отправки уведомления пользователю {login} на email {email}")
    subject = "[ТЕСТ] Требуется смена пароля"
    body = f"""Уважаемый пользователь {login},
    
Ваш пароль в системе был изменен более {PASSWORD_AGE_DAYS} дней назад.
Пожалуйста, выполните смену пароля в ближайшее время.

Это тестовое сообщение. Проигнорируйте его.

С уважением,
IT-отдел Profit SI"""
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_CONFIG['from_email']
    msg['To'] = email
    msg['Date'] = formatdate(localtime=True)
    
    try:
        logging.info(f"Подключение к SMTP серверу {SMTP_CONFIG['server']}:{SMTP_CONFIG['port']}")
        with smtplib.SMTP(SMTP_CONFIG['server'], SMTP_CONFIG['port']) as server:
            server.starttls()
            server.login(SMTP_CONFIG['user'], SMTP_CONFIG['password'])
            server.send_message(msg)
        logging.info(f"Уведомление успешно отправлено пользователю {login}")
    except Exception as e:
        logging.error(f"Ошибка при отправке email пользователю {login}: {str(e)}")

def main_loop():
    """Основной цикл проверки"""
    logging.info("Запуск основного цикла проверки")
    while True:
        try:
            logging.info("Начало новой итерации проверки паролей")
            users = get_users_with_old_passwords()
            for user in users:
                send_notification(user['email'], user['login'])
            logging.info(f"Итерация завершена. Обработано пользователей: {len(users)}")
        except Exception as e:
            logging.error(f"Критическая ошибка в основном цикле: {str(e)}")
        
        logging.info(f"Ожидание {CHECK_INTERVAL} секунд до следующей проверки")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    logging.info("Запуск приложения Password Notifier")
    main_loop()