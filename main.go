package main

import (
	"log"
	"os"

	"github.com/gliderlabs/ssh"
)

func main() {

	forwardHandler := &ssh.ForwardedTCPHandler{}

	signer, err := ReadPemFile("key.pk")
	if err != nil {
		panic(err)
	}

	authorizedKeysData, err := os.ReadFile("authorized_keys")
	if err != nil {
		panic(err)
	}

	authorizedKeys, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKeysData)
	if err != nil {
		panic(err)
	}

	server := ssh.Server{
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			//log.Println("Accepted forward", dhost, dport)
			return false
		}),
		Addr:        ":567",
		HostSigners: []ssh.Signer{signer},
		//Handler: ssh.Handler(func(s ssh.Session) {
		//	io.WriteString(s, "wsefrtergwvrwgvrtgvbrtfgvtrfd...\n")
		//	select {}
		//}),
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			log.Println("attempt to bind", host, port, "granted")
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        forwardHandler.HandleSSHRequest,
			"cancel-tcpip-forward": forwardHandler.HandleSSHRequest,
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			return false
		},
		SessionRequestCallback: func(sess ssh.Session, requestType string) bool {
			return false
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			return ssh.KeysEqual(key, authorizedKeys)
		},
	}

	log.Fatal(server.ListenAndServe())
}
