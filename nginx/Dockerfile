FROM nginx:latest

COPY /nginx/nginx.conf /etc/nginx/nginx.conf

COPY ../cert /etc/nginx/cert

EXPOSE 80 443

# Запуск Nginx
CMD ["nginx", "-g", "daemon off;"]
