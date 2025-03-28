# Этап сборки
FROM python:3.11-slim as builder

# Установка необходимых пакетов для сборки
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Создание и активация виртуального окружения
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Копирование файлов зависимостей
COPY requirements.txt .

# Установка зависимостей
RUN pip install --no-cache-dir -r requirements.txt

# Финальный этап
FROM python:3.11-slim

# Копирование виртуального окружения из этапа сборки
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Создание непривилегированного пользователя
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /opt/venv

# Установка рабочей директории
WORKDIR /app

# Создание директории для логов и установка прав доступа
RUN mkdir -p /app/logs && \
    chown -R appuser:appuser /app/logs

# Копирование файлов приложения
COPY --chown=appuser:appuser app.py .
COPY .env /app/.env

# Переключение на непривилегированного пользователя
USER appuser

# Запуск приложения
CMD ["python", "app.py"]
