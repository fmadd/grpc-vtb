@echo off
FOR /F "tokens=*" %%a IN ('curl -s -X POST http://localhost:8000/api/loginUser -H "Content-Type: application/json" -d "{\"username\": \"john_doe\", \"password\": \"password123\"}"') DO SET RESPONSE=%%a
FOR /F "tokens=2 delims=:," %%b IN ("%RESPONSE%") DO SET ACCESS_TOKEN=%%b

for /L %%i in (1, 1, 10) do (
  curl -X POST http://localhost:8000/api/validateUser ^
       -H "Content-Type: application/json" ^
       -d "{\"accessToken\": \"%ACCESS_TOKEN%\"}"
)

pause
