//go:build !windows

package nativeview

import "context"

func Run(context.Context, Remote, Options) error { return ErrUnsupported }
