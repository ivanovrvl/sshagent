package main

import (
	"errors"
	"log"
	"strings"

	"github.com/gliderlabs/ssh"
)

func main() {

	forwardHandler := &ssh.ForwardedTCPHandler{}

	err := LoadConfig()
	if err != nil {
		panic(err)
	}

	/*
		var authorizedKeys ssh.PublicKey

		authorizedKeysData, err := os.ReadFile("authorized_keys")
		if err == nil {
			authorizedKeys, _, _, _, err = ssh.ParseAuthorizedKey(authorizedKeysData)
			if err != nil {
				panic(err)
			}
		}
	*/

	var channelJandler ssh.ChannelHandler

	switch strings.ToLower(Config.ProxyType) {
	case "socks", "socks5":
		channelJandler = Socks5TCPIPHandler
	case "http", "https":
		channelJandler = HttpsTCPIPHandler
	default:
		panic(errors.New("Unsupported proxyType= " + Config.ProxyType))
	}

	var publicKeyHandler ssh.PublicKeyHandler = nil
	if Config.UseUserKeys {
		publicKeyHandler = func(ctx ssh.Context, key ssh.PublicKey) bool {
			user, ok := Config.Users[ctx.User()]
			if !ok {
				return false
			}
			if len(user.Key) == 0 {
				return false
			}
			authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey(([]byte)(user.Key))
			if err != nil {
				handle(err)
				return false
			}
			return ssh.KeysEqual(key, authorizedKey)
		}
	}

	server := ssh.Server{
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			//log.Println("Accepted forward", dhost, dport)
			return true
		}),
		Addr: Config.BindAddr,
		//HostSigners: []ssh.Signer{signer},
		//Handler: ssh.Handler(func(s ssh.Session) {
		//	io.WriteString(s, "wsefrtergwvrwgvrtgvbrtfgvtrfd...\n")
		//	select {}
		//}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			user, ok := Config.Users[ctx.User()]
			if !ok || !user.AllowRemotePort {
				return false
			}
			log.Println("attempt to bind", host, port, "granted")
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"direct-tcpip": channelJandler,
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			user, ok := Config.Users[ctx.User()]
			if !ok {
				return false
			}
			return user.Pwd == password
		},
		SessionRequestCallback: func(sess ssh.Session, requestType string) bool {
			return false
		},
		PublicKeyHandler: publicKeyHandler,
	}

	if len(Config.KeyFile) != 0 {
		err = server.SetOption(ssh.HostKeyFile(Config.KeyFile))
		if err != nil {
			panic(err)
		}
	}

	/*
		go func() {
			defer ch.Close()
			defer dconn.Close()
			io.Copy(dconn, ch)
		}()
	*/

	log.Fatal(server.ListenAndServe())
}
