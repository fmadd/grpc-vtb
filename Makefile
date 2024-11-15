gen:
	protoc --go_out=./api/proto/proto --go-grpc_out=./api/proto/proto api/proto/proto/*.proto

server:
	go run cmd/server/main.go -tls=false

server-tls:
	go run cmd/server/main.go -tls=true

client:
	go run cmd/client/client.go -tls=false

client-tls:
	go run cmd/client/client.go -tls=true

cert:
	cd cert; ./gen.sh; cd ..

.PHONY: gen clean server client test cert
