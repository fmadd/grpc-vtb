FROM golang:1.23-bullseye AS build

WORKDIR /app

COPY ../../go.mod ../../go.sum ./

RUN go mod download

COPY . .

RUN go mod tidy
ENV GOARCH=amd64
ENV GOOS=linux
RUN go build -o central-grpc-server ./cmd/server

FROM debian:bullseye-slim

COPY --from=build /app/cert /cert

COPY --from=build /app/central-grpc-server /usr/local/bin/

RUN chmod +x /usr/local/bin/central-grpc-server

EXPOSE 50051

CMD ["/usr/local/bin/central-grpc-server", "--tls", "true"]
