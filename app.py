import os
from ldap3 import Server, Connection, ALL
from datetime import datetime, timedelta, timezone
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate
import logging
from logging.handlers import RotatingFileHandler
import time
from dotenv import load_dotenv
import requests

# Создание директории для логов, если она не существует
os.makedirs('logs', exist_ok=True)

# Настройка логирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s',
    handlers=[
        RotatingFileHandler('logs/app.log', maxBytes=1024*1024, backupCount=10),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Загрузка переменных окружения из .env файла
logger.info("Загрузка переменных окружения...")
load_dotenv()
logger.info("Переменные окружения успешно загружены")

# Конфигурационные параметры
AD_CONFIG = {
    'server': os.getenv('AD_SERVER'),
    'user': os.getenv('AD_USER'),
    'password': os.getenv('AD_PASSWORD'),
    'base_dn': os.getenv('AD_BASE_DN'),
    'included_groups': os.getenv('AD_INCLUDED_GROUP').split(',')
}

SMTP_CONFIG = {
    'server': os.getenv('SMTP_SERVER'),
    'port': int(os.getenv('SMTP_PORT')),
    'user': os.getenv('SMTP_USER'),
    'password': os.getenv('SMTP_PASSWORD'),
    'from_email': os.getenv('SMTP_FROM_EMAIL')
}

TELEGRAM_CONFIG = {
    'bot_token': os.getenv('TELEGRAM_BOT_TOKEN'),
    'chat_id': os.getenv('TELEGRAM_CHAT_ID')
}

EMAIL_DOMAIN = os.getenv('EMAIL_DOMAIN')
PASSWORD_AGE_DAYS = int(os.getenv('PASSWORD_AGE_DAYS'))
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL'))

logger.info("Логирование настроено")

def convert_filetime(ft):
    """Конвертирует Windows FileTime в datetime"""
    try:
        if isinstance(ft, datetime):
            # Если дата уже имеет часовой пояс, возвращаем как есть
            if ft.tzinfo is not None:
                return ft
            # Если дата без часового пояса, добавляем UTC
            return ft.replace(tzinfo=timezone.utc)
        result = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft//10)
        logger.debug(f"Конвертация FileTime {ft} в datetime: {result}")
        return result
    except Exception as e:
        logger.error(f"Ошибка при конвертации FileTime: {str(e)}")
        raise

def get_ad_connection():
    """Устанавливает соединение с AD"""
    try:
        logger.info(f"Попытка подключения к AD серверу: {AD_CONFIG['server']}")
        server = Server(AD_CONFIG['server'], get_info=ALL)
        conn = Connection(
            server,
            user=AD_CONFIG['user'],
            password=AD_CONFIG['password'],
            auto_bind=True
        )
        logger.info("Успешное подключение к AD")
        return conn
    except Exception as e:
        logger.error(f"Ошибка при подключении к AD: {str(e)}")
        raise

def get_users_with_old_passwords():
    """Возвращает пользователей с паролями старше заданного срока"""
    logger.info("Начало поиска пользователей с устаревшими паролями")
    conn = get_ad_connection()
    
    # Поиск групп из конфигурации
    target_groups_dn = []
    for group_name in AD_CONFIG['included_groups']:
        group_search_filter = f'(&(objectClass=group)(cn={group_name}))'
        conn.search(AD_CONFIG['base_dn'], group_search_filter, attributes=['distinguishedName'])
        if not conn.entries:
            logger.error(f"Группа {group_name} не найдена")
            continue
        target_groups_dn.append(conn.entries[0].distinguishedName.value)
        logger.info(f"Найдена группа {group_name}: {conn.entries[0].distinguishedName.value}")
    
    if not target_groups_dn:
        logger.error("Не найдено ни одной группы из списка")
        return []
    
    search_filter = (
        '(&(objectCategory=person)(objectClass=user)'
        '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    )
    
    attributes = ['sAMAccountName', 'mail', 'pwdLastSet', 'distinguishedName', 'memberOf']
    
    logger.info(f"Выполнение поиска в AD с фильтром: {search_filter}")
    conn.search(AD_CONFIG['base_dn'], search_filter, attributes=attributes)
    users = []
    
    logger.info(f"Найдено пользователей в AD: {len(conn.entries)}")
    for entry in conn.entries:
        try:
            logger.debug(f"Обработка пользователя: {entry.sAMAccountName.value}")
            # Проверяем членство в целевых группах
            member_of = entry.memberOf.value if hasattr(entry, 'memberOf') and entry.memberOf.value is not None else []
            if isinstance(member_of, str):
                member_of = [member_of]
            
            logger.debug(f"Группы пользователя {entry.sAMAccountName.value}: {member_of}")
            logger.debug(f"Искомые группы: {target_groups_dn}")
            
            # Проверяем, является ли пользователь членом всех указанных групп
            is_member = all(group_dn in member_of for group_dn in target_groups_dn)
            if not is_member:
                missing_groups = [group for group in target_groups_dn if group not in member_of]
                logger.debug(f"Пользователь {entry.sAMAccountName.value} не является членом следующих групп: {missing_groups}")
                continue
                
            pwd_last_set = convert_filetime(entry.pwdLastSet.value)
            current_time = datetime.now(timezone.utc)
            delta = current_time - pwd_last_set
            
            if delta.days >= PASSWORD_AGE_DAYS:
                user_info = {
                    'login': entry.sAMAccountName.value,
                    'email': entry.mail.value or f"{entry.sAMAccountName.value}{EMAIL_DOMAIN}",
                    'last_changed': pwd_last_set
                }
                users.append(user_info)
                logger.info(f"Найден пользователь с устаревшим паролем: {user_info['login']}, последняя смена: {user_info['last_changed']}")
        except Exception as e:
            logger.error(f"Ошибка при обработке пользователя {entry.sAMAccountName}: {str(e)}")
    
    conn.unbind()
    logger.info(f"Поиск завершен. Найдено пользователей с устаревшими паролями: {len(users)}")
    return users

def send_notification(email, login):
    """Отправляет email-уведомление"""
    logger.info(f"Подготовка отправки уведомления пользователю {login} на email {email}")
    subject = "[ТЕСТ] Требуется смена пароля"
    body = f"""Уважаемый пользователь {login},
    
Ваш пароль в системе был изменен более {PASSWORD_AGE_DAYS} дней назад.
Пожалуйста, выполните смену пароля в ближайшее время.

Это тестовое сообщение. Проигнорируйте его.

С уважением,
IT-отдел Domain.example"""
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_CONFIG['from_email']
    msg['To'] = email
    msg['Date'] = formatdate(localtime=True)
    
    try:
        logger.info(f"Подключение к SMTP серверу {SMTP_CONFIG['server']}:{SMTP_CONFIG['port']}")
        with smtplib.SMTP(SMTP_CONFIG['server'], SMTP_CONFIG['port']) as server:
            server.starttls()
            server.login(SMTP_CONFIG['user'], SMTP_CONFIG['password'])
            server.send_message(msg)
        logger.info(f"Уведомление успешно отправлено пользователю {login}")
    except Exception as e:
        logger.error(f"Ошибка при отправке email пользователю {login}: {str(e)}")

def send_telegram_notification(user_info):
    """Отправляет уведомление в Telegram"""
    try:
        message = (
            f"🔔 Уведомление о устаревшем пароле\n\n"
            f"Пользователь: {user_info['login']}\n"
            f"Email: {user_info['email']}\n"
            f"Последняя смена пароля: {user_info['last_changed'].strftime('%d.%m.%Y %H:%M:%S')}\n"
            f"Прошло дней: {(datetime.now(timezone.utc) - user_info['last_changed']).days}"
        )
        
        url = f"https://api.telegram.org/bot{TELEGRAM_CONFIG['bot_token']}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CONFIG['chat_id'],
            "text": message,
            "parse_mode": "HTML"
        }
        
        response = requests.post(url, data=data)
        if response.status_code == 200:
            logger.info(f"Уведомление в Telegram успешно отправлено для пользователя {user_info['login']}")
        else:
            logger.error(f"Ошибка при отправке уведомления в Telegram: {response.text}")
    except Exception as e:
        logger.error(f"Ошибка при отправке уведомления в Telegram: {str(e)}")

def main_loop():
    """Основной цикл проверки"""
    logger.info("Запуск основного цикла проверки")
    while True:
        try:
            logger.info("Начало новой итерации проверки паролей")
            users = get_users_with_old_passwords()
            for user in users:
                send_notification(user['email'], user['login'])
                send_telegram_notification(user)
            logger.info(f"Итерация завершена. Обработано пользователей: {len(users)}")
        except Exception as e:
            logger.error(f"Критическая ошибка в основном цикле: {str(e)}")
        
        logger.info(f"Ожидание {CHECK_INTERVAL} секунд до следующей проверки")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    logger.info("Запуск приложения Password Notifier")
    main_loop()