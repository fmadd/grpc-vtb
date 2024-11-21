# Указываем базовый образ
FROM openjdk:17-jdk-slim

# Устанавливаем рабочую директорию в контейнере
WORKDIR /opt/keycloak-26.0.5

# Копируем все файлы из текущей папки и выше, включая bin и другие
COPY  /opt/keycloak-26.0.5 .

# Устанавливаем переменные окружения для Keycloak
ENV KEYCLOAK_HOME=/opt/keycloak-26.0.5
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin

RUN sed -i 's/\r$//' /opt/keycloak-26.0.5/bin/kc.sh
# Даем права на выполнение скрипта kc.sh
RUN chmod +x /opt/keycloak-26.0.5/bin/kc.sh

# Указываем команду для запуска Keycloak в режиме разработки
ENTRYPOINT ["/opt/keycloak-26.0.5/bin/kc.sh", "start-dev"]
