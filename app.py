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
import redis
import json

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

REDIS_CONFIG = {
    'host': os.getenv('REDIS_HOST', 'localhost'),
    'port': int(os.getenv('REDIS_PORT', 6379)),
    'db': int(os.getenv('REDIS_DB', 0)),
    'password': os.getenv('REDIS_PASSWORD', None)
}

EMAIL_DOMAIN = os.getenv('EMAIL_DOMAIN')
PASSWORD_AGE_DAYS = int(os.getenv('PASSWORD_AGE_DAYS'))
CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL'))

logger.info("Логирование настроено")

def init_redis_connection(max_retries=3, retry_delay=5):
    """Инициализация подключения к Redis с повторными попытками"""
    for attempt in range(max_retries):
        try:
            redis_client = redis.Redis(
                host=REDIS_CONFIG['host'],
                port=REDIS_CONFIG['port'],
                db=REDIS_CONFIG['db'],
                password=REDIS_CONFIG['password'],
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5
            )
            # Проверяем подключение
            redis_client.ping()
            logger.info("Успешное подключение к Redis")
            return redis_client
        except redis.ConnectionError as e:
            if attempt < max_retries - 1:
                logger.warning(f"Попытка подключения к Redis {attempt + 1}/{max_retries} не удалась: {str(e)}")
                logger.info(f"Повторная попытка через {retry_delay} секунд...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Не удалось подключиться к Redis после {max_retries} попыток: {str(e)}")
                raise
        except Exception as e:
            logger.error(f"Неожиданная ошибка при подключении к Redis: {str(e)}")
            raise

# Инициализация Redis
try:
    redis_client = init_redis_connection()
except Exception as e:
    logger.error(f"Критическая ошибка при инициализации Redis: {str(e)}")
    raise

def convert_filetime(ft):
    """Конвертирует Windows FileTime в datetime"""
    try:
        if isinstance(ft, datetime):
            # Если дата уже имеет часовой пояс, возвращаем как есть
            if ft.tzinfo is not None:
                return ft
            # Если дата без часового пояса, добавляем часовой пояс из переменной окружения
            return ft.replace(tzinfo=timezone(os.getenv('TZ', 'Europe/Moscow')))
        # Конвертируем FileTime в datetime с учетом часового пояса
        result = datetime(1601, 1, 1, tzinfo=timezone(os.getenv('TZ', 'Europe/Moscow'))) + timedelta(microseconds=ft//10)
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
    
    attributes = ['sAMAccountName', 'mail', 'pwdLastSet', 'distinguishedName', 'memberOf', 'givenName', 'sn']
    
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
                    'last_changed': pwd_last_set,
                    'given_name': entry.givenName.value if hasattr(entry, 'givenName') and entry.givenName.value else '',
                    'sn': entry.sn.value if hasattr(entry, 'sn') and entry.sn.value else ''
                }
                users.append(user_info)
                logger.info(f"Найден пользователь с устаревшим паролем: {user_info['login']}, последняя смена: {user_info['last_changed']}")
        except Exception as e:
            logger.error(f"Ошибка при обработке пользователя {entry.sAMAccountName}: {str(e)}")
    
    conn.unbind()
    logger.info(f"Поиск завершен. Найдено пользователей с устаревшими паролями: {len(users)}")
    return users

def send_notification(email, login, given_name='', sn='', last_changed=None):
    """Отправляет email-уведомление"""
    logger.info(f"Подготовка отправки уведомления пользователю {login} на email {email}")
    subject = "Требуется смена пароля"
    
    # Формируем полное имя пользователя
    full_name = f"{given_name} {sn}".strip()
    if not full_name:
        full_name = login
        
    # Используем реальную дату последней смены пароля из AD
    if last_changed:
        last_changed_str = last_changed.strftime('%d.%m.%Y %H:%M:%S')
        days_passed = (datetime.now(timezone.utc) - last_changed).days
    else:
        last_changed_str = "неизвестно"
        days_passed = PASSWORD_AGE_DAYS
        
    body = f"""<p style="font-weight: 400;">{full_name}!</p>
"""
    
    msg = MIMEText(body, 'html', 'utf-8')
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

def find_user_messages_in_chat(user_login):
    """Поиск сообщений о пользователе в чате"""
    try:
        # Проверяем подключение к Redis
        redis_client.ping()
        
        # Получаем все ключи из Redis, связанные с уведомлениями
        keys = redis_client.keys("telegram_notification:*")
        user_messages = []
        
        for key in keys:
            notification_data = json.loads(redis_client.get(key))
            if notification_data.get('user_login') == user_login:
                user_messages.append({
                    'message_id': notification_data.get('message_id'),
                    'key': key
                })
        
        return user_messages
    except redis.ConnectionError as e:
        logger.error(f"Ошибка подключения к Redis при поиске сообщений: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Ошибка при поиске сообщений пользователя {user_login}: {str(e)}")
        return []

def delete_telegram_message(message_id):
    """Удаление сообщения из Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_CONFIG['bot_token']}/deleteMessage"
        data = {
            "chat_id": TELEGRAM_CONFIG['chat_id'],
            "message_id": message_id
        }
        
        response = requests.post(url, data=data)
        if response.status_code == 200:
            logger.info(f"Сообщение {message_id} успешно удалено из Telegram")
            return True
        else:
            logger.error(f"Ошибка при удалении сообщения {message_id}: {response.text}")
            return False
    except Exception as e:
        logger.error(f"Ошибка при удалении сообщения {message_id}: {str(e)}")
        return False

def send_telegram_notification(user_info):
    """Отправляет уведомление в Telegram"""
    try:
        # Проверяем подключение к Redis
        redis_client.ping()
        
        # Поиск существующих сообщений о пользователе
        existing_messages = find_user_messages_in_chat(user_info['login'])
        
        # Удаляем старые сообщения
        for message in existing_messages:
            if delete_telegram_message(message['message_id']):
                try:
                    # Удаляем информацию из Redis
                    redis_client.delete(message['key'])
                    logger.info(f"Удалена информация о сообщении {message['message_id']} из Redis")
                except redis.ConnectionError as e:
                    logger.error(f"Ошибка подключения к Redis при удалении сообщения: {str(e)}")
        
        full_name = f"{user_info['given_name']} {user_info['sn']}".strip()
        if not full_name:
            full_name = user_info['login']
            
        message = (
            f"🔔 Уведомление о устаревшем пароле\n\n"
            f"Пользователь: {full_name}\n"
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
            response_data = response.json()
            message_id = response_data.get('result', {}).get('message_id')
            
            if message_id:
                try:
                    # Сохраняем информацию о сообщении в Redis
                    notification_data = {
                        'message_id': message_id,
                        'user_login': user_info['login'],
                        'user_email': user_info['email'],
                        'user_name': full_name,
                        'sent_at': datetime.now(timezone.utc).isoformat(),
                        'password_last_changed': user_info['last_changed'].isoformat()
                    }
                    
                    # Используем message_id как ключ
                    redis_key = f"telegram_notification:{message_id}"
                    redis_client.setex(
                        redis_key,
                        60 * 60 * 24 * 30,  # Храним 30 дней
                        json.dumps(notification_data)
                    )
                    logger.info(f"Информация о сообщении {message_id} сохранена в Redis")
                except redis.ConnectionError as e:
                    logger.error(f"Ошибка подключения к Redis при сохранении сообщения: {str(e)}")
            
            logger.info(f"Уведомление в Telegram успешно отправлено для пользователя {user_info['login']}")
        else:
            logger.error(f"Ошибка при отправке уведомления в Telegram: {response.text}")
    except Exception as e:
        logger.error(f"Ошибка при отправке уведомления в Telegram: {str(e)}")

def check_and_cleanup_old_messages(users_with_old_passwords):
    """Проверяет и удаляет сообщения о пользователях, чьи пароли были обновлены"""
    try:
        # Получаем все ключи из Redis
        keys = redis_client.keys("telegram_notification:*")
        if not keys:
            return

        # Создаем список логинов пользователей с устаревшими паролями
        current_users = {user['login'] for user in users_with_old_passwords}
        
        for key in keys:
            try:
                notification_data = json.loads(redis_client.get(key))
                user_login = notification_data.get('user_login')
                
                # Если пользователь не в списке текущих пользователей с устаревшими паролями,
                # значит его пароль был обновлен
                if user_login and user_login not in current_users:
                    message_id = notification_data.get('message_id')
                    if message_id:
                        if delete_telegram_message(message_id):
                            redis_client.delete(key)
                            logger.info(f"Удалено сообщение {message_id} для пользователя {user_login} (пароль обновлен)")
            except Exception as e:
                logger.error(f"Ошибка при обработке ключа {key}: {str(e)}")
                continue
                
    except redis.ConnectionError as e:
        logger.error(f"Ошибка подключения к Redis при проверке старых сообщений: {str(e)}")
    except Exception as e:
        logger.error(f"Ошибка при проверке старых сообщений: {str(e)}")

def main_loop():
    """Основной цикл проверки"""
    logger.info("Запуск основного цикла проверки")
    while True:
        try:
            logger.info("Начало новой итерации проверки паролей")
            users = get_users_with_old_passwords()
            
            # Проверяем и удаляем сообщения о пользователях с обновленными паролями
            check_and_cleanup_old_messages(users)
            
            for i, user in enumerate(users):
                send_notification(
                    user['email'], 
                    user['login'],
                    user['given_name'],
                    user['sn'],
                    user['last_changed']
                )
                send_telegram_notification(user)
                # Добавляем задержку между отправкой сообщений в Telegram (3 секунды)
                if i < len(users) - 1:  # Не ждем после последнего сообщения
                    logger.debug("Ожидание 3 секунды перед отправкой следующего сообщения в Telegram")
                    time.sleep(3)
            logger.info(f"Итерация завершена. Обработано пользователей: {len(users)}")
        except Exception as e:
            logger.error(f"Критическая ошибка в основном цикле: {str(e)}")
        
        logger.info(f"Ожидание {CHECK_INTERVAL} секунд до следующей проверки")
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    logger.info("Запуск приложения Password Notifier")
    main_loop()