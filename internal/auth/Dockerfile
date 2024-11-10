
FROM --platform=linux/amd64 golang:1.21-alpine AS build


WORKDIR /app


COPY ../../../go.mod ../../../go.sum ./


RUN go mod download


COPY . .

RUN go mod tidy


RUN go build -o auth-server ./internal/auth/main


FROM debian:bullseye-slim


COPY --from=build /app/cert /cert


COPY --from=build /app/auth-server /usr/local/bin/


RUN chmod +x /usr/local/bin/auth-server


EXPOSE 8081


CMD ["/usr/local/bin/auth-server"]
