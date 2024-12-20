## Защищённый gRPC микросервис

# Описание
Данный проект представляет собой безопасный gRPC микросервис, который обеспечивает защищенную передачу данных между клиентом и сервером. Используя шифрование TLS, сервер гарантирует конфиденциальность данных, передаваемых по сети.
Весь сервис работает в контейнерах Docker, что обеспечивает простоту развертывания и масштабируемость.

# Особенности
Поддержка шифрования TLS
Аутентификация и авторизация пользователей
Логирование запросов и ответов
Высокая производительность и масштабируемость

# Требования
Go версии 1.23 или выше

# Запуск сервиса
Для запуска выполните команду:
docker-compose up

#Пример запроса к серверу
Пример обращения клиентской части для создания пользователя:

```
curl -X POST http://localhost:8000/api/registerUser ^
  -H "Content-Type: application/json" ^
  -d "{\"username\": \"john_doe\", \"email\": \"john_doe@example.com\", \"password\": \"password123\"}"
```

Пример обращения клиентской части для авторизации пользователя:
```
'curl -X POST http://localhost:8000/api/loginUser -H "Content-Type: application/json" -d "{\"username\": \"john_doe\", \"password\": \"password123\"}"
```

# Логирование
Сервер осуществляет логирование входящих запросов и исходящих ответов, что позволяет отслеживать действия пользователей и производить аудит.