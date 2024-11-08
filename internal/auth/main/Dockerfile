# Используем официальный образ Go
FROM golang:1.19-alpine as build

# Устанавливаем рабочую директорию в контейнере
WORKDIR /app

# Копируем исходный код в контейнер
COPY . .

# Устанавливаем зависимости
RUN go mod tidy

# Собираем приложение
RUN go build -o auth-server .

# Базовый образ для финального контейнера
FROM alpine:latest

# Устанавливаем сертификаты
COPY --from=build /app/cert /cert

# Копируем скомпилированный бинарник
COPY --from=build /app/auth-server /usr/local/bin/

# Открываем порты
EXPOSE 8081

# Запускаем приложение
CMD ["/usr/local/bin/auth-server"]
