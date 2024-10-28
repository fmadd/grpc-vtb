# grpc-vtb
# для геенрации сертификатов main/crt_storage/: openssl req -new -x509 -nodes -days 365 -keyout private/server.key -out certs/server.crt -config openssl.cnf
# для генерации protobuf main/: protoc --go_out=./api/proto --go-grpc_out=./api/proto api\proto\quotes.proto