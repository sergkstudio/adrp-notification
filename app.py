import os
from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
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
import pytz
import random
import string
import ssl
from ldap3.utils.dn import DN
from ldap3.protocol.rfc2251 import Tls


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

# Получение системного часового пояса
local_tz = pytz.timezone(os.getenv('TZ', 'Europe/Moscow'))
logger.info(f"Используется часовой пояс: {local_tz}")
logger.info(f"Текущее время в локальном часовом поясе: {datetime.now(local_tz).strftime('%d.%m.%Y %H:%M:%S %Z')}")

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
            # Если дата уже имеет часовой пояс, конвертируем в локальный
            if ft.tzinfo is not None:
                logger.debug(f"Дата до конвертации: {ft.strftime('%d.%m.%Y %H:%M:%S %Z')}")
                local_dt = ft.astimezone(local_tz)
                logger.debug(f"Дата после конвертации в {local_tz}: {local_dt.strftime('%d.%m.%Y %H:%M:%S %Z')}")
                return local_dt
            # Если дата без часового пояса, добавляем системный часовой пояс
            localized_dt = local_tz.localize(ft)
            logger.debug(f"Дата локализована в часовой пояс {local_tz}: {localized_dt.strftime('%d.%m.%Y %H:%M:%S %Z')}")
            return localized_dt
        # Для FileTime создаем дату в UTC и конвертируем в локальный часовой пояс
        utc_dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft//10)
        local_dt = utc_dt.astimezone(local_tz)
        logger.debug(f"Конвертация FileTime {ft} в datetime: {local_dt.strftime('%d.%m.%Y %H:%M:%S %Z')}")
        return local_dt
    except Exception as e:
        logger.error(f"Ошибка при конвертации FileTime: {str(e)}")
        raise

def get_ad_connection():
    """Устанавливает соединение с AD"""
    try:
        logger.info(f"Попытка подключения к AD серверу: {AD_CONFIG['server']}")
        server = Server(
            AD_CONFIG['server'],
            get_info=ALL,
            use_ssl=False,  # Отключаем SSL, так как будем использовать STARTTLS
            tls=Tls(validate=ssl.CERT_NONE)  # Отключаем проверку сертификата
        )
        
        conn = Connection(
            server,
            user=AD_CONFIG['user'],
            password=AD_CONFIG['password'],
            auto_bind=False  # Отключаем автоматическую привязку
        )
        
        # Устанавливаем STARTTLS соединение
        if conn.start_tls():
            logger.info("STARTTLS соединение успешно установлено")
        else:
            logger.error("Не удалось установить STARTTLS соединение")
            raise Exception("Ошибка установки STARTTLS соединения")
            
        # Выполняем привязку после установки STARTTLS
        if conn.bind():
            logger.info("Успешное подключение к AD")
            return conn
        else:
            logger.error(f"Ошибка привязки к AD: {conn.result}")
            raise Exception("Ошибка привязки к AD")
            
    except Exception as e:
        logger.error(f"Ошибка при подключении к AD: {str(e)}")
        raise

def get_users_with_old_passwords():
    """Возвращает пользователей с паролями старше заданного срока"""
    logger.info("Начало поиска пользователей с устаревшими паролями")
    conn = get_ad_connection()
    
    # Получаем текущую дату в системном часовом поясе
    current_date = datetime.now(local_tz)
    cutoff_date = current_date - timedelta(days=PASSWORD_AGE_DAYS)
    logger.info(f"Текущая дата: {current_date.strftime('%d.%m.%Y %H:%M:%S %Z')}")
    logger.info(f"Дата отсечки: {cutoff_date.strftime('%d.%m.%Y %H:%M:%S %Z')}")
    
    # Проверяем, указан ли тестовый пользователь
    test_user_name = os.getenv('TEST_USER_NAME')
    test_user_sn = os.getenv('TEST_USER_SN')
    
    if test_user_name and test_user_sn:
        logger.info(f"Тестовый режим: поиск пользователя {test_user_name} {test_user_sn}")
        search_filter = f'(&(objectCategory=person)(objectClass=user)(givenName={test_user_name})(sn={test_user_sn}))'
        attributes = ['sAMAccountName', 'mail', 'pwdLastSet', 'distinguishedName', 'memberOf', 'givenName', 'sn']
        
        logger.info(f"Выполнение поиска в AD с фильтром: {search_filter}")
        conn.search(AD_CONFIG['base_dn'], search_filter, attributes=attributes)
        users = []
        
        for entry in conn.entries:
            try:
                pwd_last_set = convert_filetime(entry.pwdLastSet.value)
                user_info = {
                    'login': entry.sAMAccountName.value,
                    'email': entry.mail.value or f"{entry.sAMAccountName.value}{EMAIL_DOMAIN}",
                    'last_changed': pwd_last_set,
                    'given_name': entry.givenName.value if hasattr(entry, 'givenName') and entry.givenName.value else '',
                    'sn': entry.sn.value if hasattr(entry, 'sn') and entry.sn.value else ''
                }
                users.append(user_info)
                logger.info(f"Найден тестовый пользователь: {user_info['login']}, последняя смена: {user_info['last_changed']}")
            except Exception as e:
                logger.error(f"Ошибка при обработке тестового пользователя: {str(e)}")
        
        conn.unbind()
        return users
    
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
            
            if pwd_last_set <= cutoff_date:
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

def generate_password(length=16):
    """Генерирует случайный пароль"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(characters) for _ in range(length))

def change_user_password(conn, user_dn, new_password):
    """Меняет пароль пользователя в AD"""
    try:
        # Формируем изменения для AD
        changes = {
            'unicodePwd': [(MODIFY_REPLACE, [new_password.encode('utf-16-le')])],
            'pwdLastSet': [(MODIFY_REPLACE, [0])]  # Требует смены пароля при следующем входе
        }
        
        # Применяем изменения
        if conn.modify(user_dn, changes):
            logger.info(f"Пароль успешно изменен для пользователя {user_dn}")
            return True
        else:
            logger.error(f"Ошибка при изменении пароля для пользователя {user_dn}: {conn.result}")
            return False
    except Exception as e:
        logger.error(f"Ошибка при изменении пароля: {str(e)}")
        return False

def get_notification_count(user_login):
    """Получает количество отправленных уведомлений для пользователя"""
    try:
        count = redis_client.get(f"notification_count:{user_login}")
        return int(count) if count else 0
    except Exception as e:
        logger.error(f"Ошибка при получении количества уведомлений: {str(e)}")
        return 0

def increment_notification_count(user_login):
    """Увеличивает счетчик отправленных уведомлений"""
    try:
        current_count = get_notification_count(user_login)
        new_count = current_count + 1
        redis_client.setex(f"notification_count:{user_login}", 86400 * 30, new_count)  # Храним 30 дней
        return new_count
    except Exception as e:
        logger.error(f"Ошибка при увеличении счетчика уведомлений: {str(e)}")
        return 0

def reset_notification_count(user_login):
    """Сбрасывает счетчик отправленных уведомлений"""
    try:
        redis_client.delete(f"notification_count:{user_login}")
        logger.info(f"Счетчик уведомлений сброшен для пользователя {user_login}")
    except Exception as e:
        logger.error(f"Ошибка при сбросе счетчика уведомлений: {str(e)}")

def send_notification(email, login, given_name='', sn='', last_changed=None):
    """Отправляет email-уведомление"""
    logger.info(f"Подготовка отправки уведомления пользователю {login} на email {email}")
    
    # Проверяем количество отправленных уведомлений
    notification_count = get_notification_count(login)
    if notification_count >= 5:
        logger.warning(f"Пользователь {login} получил уже 5 уведомлений. Генерируем новый пароль.")
        
        # Получаем подключение к AD
        conn = get_ad_connection()
        
        # Генерируем новый пароль
        new_password = generate_password()
        
        # Получаем DN пользователя
        conn.search(AD_CONFIG['base_dn'], f'(sAMAccountName={login})', attributes=['distinguishedName'])
        if not conn.entries:
            logger.error(f"Пользователь {login} не найден в AD")
            return
            
    subject = "Требуется смена пароля"
    
    # Формируем полное имя пользователя
    full_name = f"{given_name} {sn}".strip()
    if not full_name:
        full_name = login
        
    # Используем реальную дату последней смены пароля из AD
    if last_changed:
        last_changed_str = last_changed.strftime('%d.%m.%Y %H:%M:%S')
        days_passed = (datetime.now(local_tz) - last_changed).days
    else:
        last_changed_str = "неизвестно"
        days_passed = PASSWORD_AGE_DAYS
        
    body = f"""<p style="font-weight: 400;">{full_name}!</p>
<p style="font-weight: 400;"><strong>Вам необходимо сменить свой пароль для доступа к информационным системам.</strong></p>
<p style="font-weight: 400;">Последняя смена пароля: <span style="color: #ff0000;">{last_changed_str}</span></p>
<p style="font-weight: 400;">Прошло дней с последней смены пароля: <span style="color: #ff0000;">{days_passed}</span></p>
<p style="font-weight: 400;">Для смены пароля нажмите на ссылку: <a href="https://password.adrp.ru">https://password.adrp.ru</a></p>
<p style="font-weight: 400;"><strong>Внимание!</strong> Рекомендуется менять пароль не реже чем раз в 180 дней.</p>
<p style="font-weight: 400;">Если вы не запрашивали смену пароля, проигнорируйте это письмо.</p>"""

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
        # Увеличиваем счетчик отправленных уведомлений
        increment_notification_count(login)
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
            f"Прошло дней: {(datetime.now(local_tz) - user_info['last_changed']).days}"
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
                        'sent_at': datetime.now(local_tz).isoformat(),
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