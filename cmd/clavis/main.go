// Command clavis runs the Clavis identity server.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/clavis-id/clavis/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Environ())
	stop()
	os.Exit(code)
}
