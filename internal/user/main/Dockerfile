
FROM --platform=linux/amd64 golang:1.21-alpine as build


WORKDIR /app


COPY ../../../go.mod ../../../go.sum ./


RUN go mod download


COPY . .


RUN go mod tidy


RUN go build -o user-server ./internal/user/main


FROM debian:bullseye-slim


COPY --from=build /app/cert /cert


COPY --from=build /app/user-server /usr/local/bin/


RUN chmod +x /usr/local/bin/user-server


EXPOSE 50053


CMD ["/usr/local/bin/user-server"]
