# Используем официальный образ Go
FROM golang:1.19-alpine as build


WORKDIR /app


COPY . .


RUN go mod tidy


RUN go build -o user-server .


FROM alpine:latest


COPY --from=build /app/cert /cert


COPY --from=build /app/user-server /usr/local/bin/


EXPOSE 50053


CMD ["/usr/local/bin/user-server"]
