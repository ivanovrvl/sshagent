package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

var sock5req1 = [...]byte{5, 1, 2}

func writeBlock(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return errors.New("Can`t write")
	}
	return nil
}

func readBlock(r io.Reader, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		if err != nil {
			return err
		}
		if n > 0 {
			total += n
		}
	}
	return nil
}

func Socks5TCPIPHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
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

	// RFC1928 запрос со списком методов аутентификации
	err = writeBlock(dconn, sock5req1[:])
	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	// RFC1928 ответ, должен быть предложен метод аутентификации 0x02
	var resp2 [2]byte
	err = readBlock(dconn, resp2[:])
	if err == nil {
		if resp2[0] != 5 {
			err = errors.New("Byte 0x05 is expected")
		} else if resp2[1] != 2 {
			err = errors.New("Socks METHOD 0x02 is expected")
		}
	}
	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	// RFC1929 отправляем логин и пароль
	var user = ctx.User()
	var authData = []byte{1, byte(len(user))}
	authData = append(authData, []byte(user)...)
	authData = append(authData, byte(len(Config.ProxyPwd)))
	authData = append(authData, []byte(Config.ProxyPwd)...)
	err = writeBlock(dconn, []byte(authData))
	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	// RFC1929 читаем результат аутентификации
	err = readBlock(dconn, resp2[:])
	if err == nil {
		if resp2[0] != 5 {
			err = errors.New("ver=0x5 is expected")
		} else if resp2[1] != 0 {
			err = errors.New("Auth failed with code " + hex.EncodeToString(resp2[1:2]))
		}
	}
	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	portBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(portBytes, d.DestPort)

	// RFC1928 отправляем запрос на CONNECT
	var reqData = []byte{5, 1, 0, 3, byte(len(d.DestAddr))}
	reqData = append(reqData, []byte(d.DestAddr)...)
	reqData = append(reqData, portBytes[1])
	reqData = append(reqData, portBytes[0])
	err = writeBlock(dconn, []byte(reqData))
	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

	// RFC1928 читаем ответ на CONNECT шаг 1
	var resp5 [5]byte
	err = readBlock(dconn, resp5[:])
	if err == nil {
		if resp5[0] != 5 {
			err = errors.New("ver=0x5 is expected")
		} else if resp5[1] != 0 {
			err = errors.New("CONNECT failed with code " + hex.EncodeToString(resp5[1:2]))
		}
	}
	if err != nil {
		dconn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	var addrLen int
	switch resp5[3] {
	case 1:
		addrLen = 4
	case 3:
		addrLen = int(resp5[4])
	case 4:
		addrLen = 16
	default:
		dconn.Close()
		err = errors.New("Unsupported address type " + hex.EncodeToString(resp5[3:4]))
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	err = readBlock(dconn, make([]byte, addrLen+1))
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
		io.Copy(ch, dconn)
	}()
	go func() {
		defer ch.Close()
		defer dconn.Close()
		io.Copy(dconn, ch)
	}()
}
