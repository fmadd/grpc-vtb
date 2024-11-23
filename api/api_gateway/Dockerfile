FROM golang:1.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o api_server ./api/api_gateway

FROM debian:bookworm

WORKDIR /app

COPY --from=builder /app/api_server .

COPY ./cert ./cert

ENV PORT=8000
EXPOSE 8000

CMD ["./api_server"]
