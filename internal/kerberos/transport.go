package kerberos

import (
	"context"
	"encoding/binary"
	"io"
	"net"
)

// exchange keeps the configured KDC fixed. Only an explicit KRB_ERR_RESPONSE_TOO_BIG
// can retry a UDP request over TCP; timeouts and errors never replay credentials.
func (c *Client) exchange(ctx context.Context, request []byte) ([]byte, error) {
	if len(request) == 0 || len(request) > MaxMessage {
		return nil, ErrInvalid
	}
	if c.proxy != nil {
		return c.proxy.Exchange(ctx, c.config.Realm, request)
	}
	network := c.config.Network
	if network == "udp" && len(request) > 65507 {
		network = "tcp"
	}
	response, err := exchangeOnce(ctx, network, c.config.KDC, request)
	if err != nil {
		return nil, err
	}
	if network == "udp" && len(response) > 0 && response[0] == 0x7e {
		remote, err := parseError(response)
		if err != nil {
			return nil, err
		}
		if remote.Code == 52 {
			return exchangeOnce(ctx, "tcp", c.config.KDC, request)
		}
	}
	return response, nil
}

func exchangeOnce(ctx context.Context, network, address string, request []byte) (response []byte, err error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	defer func() {
		if ctx.Err() != nil {
			response = nil
			err = ctx.Err()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err = conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	if network == "udp" {
		n, err := conn.Write(request)
		if err != nil {
			return nil, err
		}
		if n != len(request) {
			return nil, io.ErrShortWrite
		}
		buf := make([]byte, 65536)
		n, err = conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, ErrInvalid
		}
		return buf[:n], nil
	}
	wire := binary.BigEndian.AppendUint32(nil, uint32(len(request)))
	wire = append(wire, request...)
	for len(wire) > 0 {
		n, err := conn.Write(wire)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			return nil, io.ErrShortWrite
		}
		wire = wire[n:]
	}
	var header [4]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxMessage {
		return nil, ErrInvalid
	}
	response = make([]byte, int(n))
	if _, err = io.ReadFull(conn, response); err != nil {
		return nil, err
	}
	return response, nil
}
