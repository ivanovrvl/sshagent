set GOARCH=amd64
set GOOS=linux
go build -o ssh2proxy -ldflags="-s -w"