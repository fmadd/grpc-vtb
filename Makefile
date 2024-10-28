gen:
	protoc --go_out=./api/proto --go-grpc_out=./api/proto api/proto/proto/*.proto
clean:
	rm pb/*.go

server:
	go run cmd/server/main.go

client:
	go run cmd/client/client.go 

cert:
	cd cert; ./gen.sh; cd ..

.PHONY: gen clean server client test cert
