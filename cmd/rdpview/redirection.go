package main

import (
	"context"
	"errors"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/internal/redirectconfig"
)

type redirectionInfoRemote interface {
	RedirectionInfo() rdp.RedirectionStatus
}
type redirectionFunc func(context.Context, remote, *rdp.RedirectionError) (remote, rdp.SessionInfo, error)

func redirectionPending(r remote) bool {
	if s, ok := r.(redirectionInfoRemote); ok {
		info := s.RedirectionInfo()
		return info.Enabled && info.Pending
	}
	return false
}

// A successful target Session, rather than the proposed server names, chooses
// the credentials for subsequent ARC. Initial credentials are released after a
// successful handoff; there is never a fallback to the original account.
func configureTransitions(v *viewer, stored *credentialsStore, plan *redirectconfig.Plan) {
	if plan != nil {
		v.follow = func(ctx context.Context, old remote, request *rdp.RedirectionError) (remote, rdp.SessionInfo, error) {
			s, ok := old.(*rdp.Session)
			if !ok {
				return nil, rdp.SessionInfo{}, rdp.ErrRedirectionUnavailable
			}
			next, err := s.FollowRedirection(ctx, request)
			if err != nil {
				return nil, rdp.SessionInfo{}, err
			}
			if stored != nil {
				stored.clear()
			}
			return next, next.Info(), nil
		}
	}
	if stored != nil {
		v.recover = func(ctx context.Context, old remote, handle recoveryEventHandler) (remote, rdp.SessionInfo, error) {
			s, ok := old.(*rdp.Session)
			if !ok {
				return nil, rdp.SessionInfo{}, rdp.ErrReconnectUnavailable
			}
			c, err := recoveryCredentials(s, stored, plan)
			if err != nil {
				return nil, rdp.SessionInfo{}, err
			}
			next, err := s.ReconnectWithEvents(ctx, c, rdp.ReconnectPolicy{}, func(ctx context.Context, candidate *rdp.Session, e rdp.Event) error {
				return handle(ctx, candidate, candidate.Info(), e)
			})
			if err != nil {
				return nil, rdp.SessionInfo{}, err
			}
			return next, next.Info(), nil
		}
	}
}

func recoveryCredentials(s redirectionInfoRemote, initial *credentialsStore, plan *redirectconfig.Plan) (rdp.Credentials, error) {
	if hop := s.RedirectionInfo().Hops; hop > 0 {
		if plan == nil {
			return rdp.Credentials{}, errors.New("redirected session has no credential plan")
		}
		return plan.Credentials(hop)
	}
	return initial.get(), nil
}

func (v *viewer) redirectConnection(ctx context.Context, old remote, request *rdp.RedirectionError) error {
	if request.Request != nil {
		defer request.Request.Clear()
	}
	// Keep old.Close until FollowRedirection returns: explicit Close cancels the
	// protocol's redirection operation. Local resources are stopped and joined
	// before dialing any successor.
	if err := v.beginTransition(ctx, true); err != nil {
		return err
	}
	if err := v.finishSources(); err != nil {
		return err
	}
	v.clipMu.Lock()
	job := v.fileJob
	v.clipMu.Unlock()
	if job != nil {
		select {
		case <-job.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	next, info, err := v.follow(ctx, old, request)
	if err != nil {
		return err
	}
	if err := v.installCandidate(ctx, next, info, nil); err != nil {
		next.Close()
		return err
	}
	old.Close()
	return refreshReplacement(ctx, next, info)
}
