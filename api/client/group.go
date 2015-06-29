package client

import (
	"errors"

	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/info"
)

type Strategy int

const (
	StrategyOrderedList = iota + 1
)

type Group interface {
	AuthSign(req, id []byte, provider auth.Provider) ([]byte, error)
	Sign(jsonData []byte) ([]byte, error)
	Info(jsonData []byte) (*info.Resp, error)
}

func NewGroup(remotes []string, strategy Strategy) (Group, error) {
	var servers = make([]*Server, len(remotes))
	for i := range remotes {
		servers[i] = NewServer(remotes[i])
	}

	switch strategy {
	case StrategyOrderedList:
		return newOrdererdListGroup(servers)
	default:
		return nil, errors.New("unrecognised strategy")
	}
}

type orderedListGroup struct {
	remotes []*Server
}

func newOrdererdListGroup(remotes []*Server) (Group, error) {
	return &orderedListGroup{
		remotes: remotes,
	}, nil
}

func (g *orderedListGroup) AuthSign(req, id []byte, provider auth.Provider) (resp []byte, err error) {
	for i := range g.remotes {
		resp, err = g.remotes[i].AuthSign(req, id, provider)
		if err == nil {
			return resp, nil
		}
	}

	return nil, err
}

func (g *orderedListGroup) Sign(jsonData []byte) (resp []byte, err error) {
	for i := range g.remotes {
		resp, err = g.remotes[i].Sign(jsonData)
		if err == nil {
			return resp, nil
		}
	}

	return nil, err
}

func (g *orderedListGroup) Info(jsonData []byte) (resp *info.Resp, err error) {
	for i := range g.remotes {
		resp, err = g.remotes[i].Info(jsonData)
		if err == nil {
			return resp, nil
		}
	}

	return nil, err
}
