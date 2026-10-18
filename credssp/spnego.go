package credssp

import (
	"bytes"
	"github.com/hq0101/rdp-go/internal/spnego"
)

var ntlmOID = []byte(spnego.NTLMOID)

const maxSPNEGOToken = spnego.MaxToken

func mechanismList() []byte                                { return spnego.NTLMList() }
func spnegoInit(token []byte) []byte                       { return spnego.Initial(token, mechanismList()) }
func spnegoInitMechanisms(token, mechanisms []byte) []byte { return spnego.Initial(token, mechanisms) }
func spnegoAuthenticate(token, mic []byte) []byte          { return spnego.Authenticate(token, mic) }

type spnegoResponse struct {
	state                 int
	mechanism, token, mic []byte
}

func parseSPNEGOResponse(b []byte) (spnegoResponse, error) {
	r, err := spnego.ParseResponse(b)
	if err != nil {
		return spnegoResponse{state: -1}, ErrProtocol
	}
	return spnegoResponse{r.State, r.Mechanism, r.Token, r.MIC}, nil
}
func spnegoChallenge(b []byte) ([]byte, error) {
	r, err := parseSPNEGOResponse(b)
	if err != nil || (r.state != 1 && r.state != 3) || !bytes.Equal(r.mechanism, ntlmOID) || len(r.token) == 0 || r.mic != nil {
		return nil, ErrProtocol
	}
	return r.token, nil
}
