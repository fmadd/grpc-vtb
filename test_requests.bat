@echo off

echo.
echo START TEST CREATE USER
echo.

curl -X POST http://localhost:8000/api/createUser ^
  -H "Content-Type: application/json" ^
  -d "{\"username\": \"john_doe\", \"email\": \"john_doe@example.com\", \"password\": \"password123\"}"

echo.
echo START TEST LOGIN USER
echo.

curl -X POST http://localhost:8000/api/loginUser ^
  -H "Content-Type: application/json" ^
  -d "{\"username\": \"john_doe\", \"password\": \"password123\"}"

FOR /F "tokens=*" %%a IN ('curl -s -X POST http://localhost:8000/api/loginUser -H "Content-Type: application/json" -d "{\"username\": \"john_doe\", \"password\": \"password123\"}"') DO SET RESPONSE=%%a
FOR /F "tokens=2 delims=:," %%b IN ("%RESPONSE%") DO SET ACCESS_TOKEN=%%b


echo.
echo START TEST VALIDATE TOKEN
echo.

curl -X POST http://localhost:8000/api/validateUser ^
  -H "Content-Type: application/json" ^
  -d "{\"accessToken\": \"%ACCESS_TOKEN%\"}"

echo.
echo START TEST SQL INJECTION
echo.

curl -X POST http://localhost:8000/api/createUser ^
    -H "Content-Type: application/json" ^
    -d "{\"username\": \"admin'; DROP TABLE users;--\", \"password\": \"password123\"}"