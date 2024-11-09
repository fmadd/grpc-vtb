# Базовый образ
FROM golang:1.20 as builder


WORKDIR /app


COPY go.mod go.sum ./


RUN go mod download


COPY . .


RUN go build -o central-grpc-server ./cmd/central_grpc_server


FROM gcr.io/distroless/base-debian11


COPY --from=builder /app/cert /cert


COPY --from=builder /app/central-grpc-server /central-grpc-server


EXPOSE 50051


CMD ["/central-grpc-server", "--tls", "true"]
