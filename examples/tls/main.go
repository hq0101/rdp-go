// Example: go run ./examples/tls server.example:3389
// This establishes transport only. An NLA-required server is expected to reject it.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/x224"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: tls host:port")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tr, err := rdp.DialTLS(ctx, os.Args[1], rdp.Options{})
	if errors.Is(err, x224.ErrNLARequired) {
		log.Fatal("server requires NLA; use DialNLA or DialChannels (see examples/nla)")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer tr.Close()
	fmt.Println("Verified TLS transport established. No user login or desktop session has occurred.")
}
