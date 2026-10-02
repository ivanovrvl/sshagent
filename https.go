package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func HttpsTCPIPHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	//dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))
	dest := net.JoinHostPort(Config.ProxyHost, strconv.FormatInt(int64(Config.ProxyPort), 10))

	var dialer net.Dialer
	dconn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	r := bufio.NewReader(dconn)
	w := bufio.NewWriter(dconn)

	crlf := "\r\n"

	target := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	_, err = w.WriteString("CONNECT " + target + " HTTP/1.1" + crlf)
	if err == nil {
		_, err = w.WriteString("Host: " + target + crlf)
	}
	if err == nil {
		_, err = w.WriteString("Proxy-Authorization: Basic " + basicAuth(ctx.User(), Config.ProxyPwd) + crlf)
	}
	if err == nil {
		_, err = w.WriteString(crlf)
	}
	if err == nil {
		w.Flush()
	}

	if err == nil {
		b, ov, err := r.ReadLine()
		if err == nil {
			if ov {
				err = errors.New("Buffer overflow")
			} else {
				a := strings.Split(string(b), " ")
				if len(a) < 2 {
					err = errors.New("Wrong response: " + string(b))
				} else {
					if a[1] != "200" {
						err = errors.New("Wrong response: " + string(b))
					} else {
						_, _, err = r.ReadLine()
					}
				}
			}
		}
	}

	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		dconn.Close()
		return
	}
	go gossh.DiscardRequests(reqs)

	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(ch, r)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
	}()
}
