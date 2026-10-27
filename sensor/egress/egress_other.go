//go:build !linux

package egress

import (
	"context"
	"errors"

	"github.com/AmanamIsrael/lookout/event"
)

// Options configures Run.
type Options struct{ Loopback bool }

// Run is unavailable off Linux: egress capture uses eBPF.
func Run(context.Context, Options, func(event.Egress)) error {
	return errors.New("egress capture needs Linux (eBPF)")
}
