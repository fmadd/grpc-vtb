# Используем официальный образ Nginx
FROM nginx:latest

# Копируем конфиг в контейнер
COPY nginx.conf /etc/nginx/nginx.conf

# Копируем сертификаты в контейнер
COPY cert /etc/nginx/cert

# Открываем порты для HTTP (80) и HTTPS (443)
EXPOSE 80 443

# Запуск Nginx
CMD ["nginx", "-g", "daemon off;"]
