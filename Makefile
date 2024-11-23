gen:
	protoc --go_out=./api/proto/proto --go-grpc_out=./api/proto/proto api/proto/proto/*.proto

start:
	docker-compose up -d

test:
	test_requests.bat
	test_ddos-attack.bat