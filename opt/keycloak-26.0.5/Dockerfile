# Указываем базовый образ
FROM openjdk:17-jdk-slim

# Устанавливаем рабочую директорию в контейнере
WORKDIR /opt/keycloak-26.0.5

# Устанавливаем переменные окружения для Keycloak
ENV KEYCLOAK_HOME=/opt/keycloak-26.0.5
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin

# Копируем все файлы из локальной папки проекта в контейнер
COPY /opt/keycloak-26.0.5 .

# Даем права на выполнение скриптов Keycloak
RUN chmod +x /opt/keycloak-26.0.5/bin/kc.sh

# Указываем команду для запуска Keycloak в режиме разработки
ENTRYPOINT ["/opt/keycloak-26.0.5/bin/kc.sh", "start-dev"]
