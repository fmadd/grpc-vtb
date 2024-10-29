module github.com/grpc-vtb

go 1.21

require google.golang.org/grpc v1.67.1

require github.com/golang/protobuf v1.5.4

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1 // indirect
)

require (
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240814211410-ddb44dafa142 // indirect
	google.golang.org/protobuf v1.35.1 // indirect; direct
)
