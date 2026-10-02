set GOARCH=amd64
set GOOS=linux
go build -o ssh2socks -ldflags="-s -w"