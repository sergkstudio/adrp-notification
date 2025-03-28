FROM python:3.9-slim

# Установка необходимых библиотек
RUN pip install ldap3

# Копирование приложения в контейнер
COPY app.py /app/app.py
COPY .env /app/.env

# Установка рабочей директории
WORKDIR /app

# Запуск приложения
CMD ["python", "app.py"]
