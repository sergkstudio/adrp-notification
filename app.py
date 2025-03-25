import os
from ldap3 import Server, Connection, ALL
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate
import logging
import time
from dotenv import load_dotenv

# Загрузка переменных окружения из .env файла
load_dotenv()

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
    filename='password_notifier.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def convert_filetime(ft):
    """Конвертирует Windows FileTime в datetime"""
    return datetime(1601, 1, 1) + timedelta(microseconds=ft//10)

def get_ad_connection():
    """Устанавливает соединение с AD"""
    server = Server(AD_CONFIG['server'], get_info=ALL)
    return Connection(
        server,
        user=AD_CONFIG['user'],
        password=AD_CONFIG['password'],
        auto_bind=True
    )

def get_users_with_old_passwords():
    """Возвращает пользователей с паролями старше заданного срока"""
    conn = get_ad_connection()
    ou_filter = '(|{})'.format(''.join([f'(distinguishedName={ou})' for ou in AD_CONFIG['included_ous']]))
    
    search_filter = (
        '(&(objectCategory=person)(objectClass=user)'
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        f'{ou_filter})'
    )
    
    attributes = ['sAMAccountName', 'mail', 'pwdLastSet', 'distinguishedName']
    
    conn.search(AD_CONFIG['base_dn'], search_filter, attributes=attributes)
    users = []
    
    for entry in conn.entries:
        try:
            pwd_last_set = convert_filetime(entry.pwdLastSet.value)
            delta = datetime.now() - pwd_last_set
            
            if delta.days >= PASSWORD_AGE_DAYS:
                users.append({
                    'login': entry.sAMAccountName.value,
                    'email': entry.mail.value or f"{entry.sAMAccountName.value}{EMAIL_DOMAIN}",
                    'last_changed': pwd_last_set
                })
        except Exception as e:
            logging.error(f"Error processing user {entry.sAMAccountName}: {str(e)}")
    
    conn.unbind()
    return users

def send_notification(email, login):
    """Отправляет email-уведомление"""
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
        with smtplib.SMTP(SMTP_CONFIG['server'], SMTP_CONFIG['port']) as server:
            server.starttls()
            server.login(SMTP_CONFIG['user'], SMTP_CONFIG['password'])
            server.send_message(msg)
        logging.info(f"Sent test notification to {email}")
    except Exception as e:
        logging.error(f"Failed to send email to {email}: {str(e)}")

def main_loop():
    """Основной цикл проверки"""
    while True:
        try:
            logging.info("Starting password check...")
            users = get_users_with_old_passwords()
            for user in users:
                send_notification(user['email'], user['login'])
            logging.info(f"Processed {len(users)} users")
        except Exception as e:
            logging.error(f"Critical error: {str(e)}")
        
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main_loop()