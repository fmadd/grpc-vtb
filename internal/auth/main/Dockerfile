# Используем официальный образ Go
FROM golang:1.19-alpine as build


WORKDIR /app


COPY . .


RUN go mod tidy


RUN go build -o auth-server .


FROM alpine:latest


COPY --from=build /app/cert /cert


COPY --from=build /app/auth-server /usr/local/bin/


EXPOSE 8081


CMD ["/usr/local/bin/auth-server"]
