
FROM --platform=linux/amd64 golang:1.21 as builder


WORKDIR /app


COPY ../../go.mod ../../go.sum ./


RUN go mod download


COPY . .


RUN go build -o central-grpc-server ./cmd/server


RUN chmod +x central-grpc-server


FROM gcr.io/distroless/base-debian11


COPY --from=builder /app/cert /cert


COPY --from=builder /app/central-grpc-server /central-grpc-server


EXPOSE 50051


CMD ["/central-grpc-server", "--tls", "true"]
