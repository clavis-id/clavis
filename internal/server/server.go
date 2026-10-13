// Package server runs an HTTP server with graceful shutdown.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// maxHeaderBytes caps request header size. Protocol requests carry small
// headers; anything larger is rejected before reaching a handler.
const maxHeaderBytes = 64 << 10

// Options configures Serve.
type Options struct {
	Handler           http.Handler
	Logger            *slog.Logger
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	// ShutdownTimeout bounds how long in-flight requests may take to finish
	// once ctx is canceled. Connections still open after it are closed.
	ShutdownTimeout time.Duration
}

// Serve accepts HTTP connections on ln until ctx is canceled, then shuts
// down gracefully. It returns nil after a clean shutdown.
func Serve(ctx context.Context, ln net.Listener, opts Options) error {
	srv := &http.Server{
		Handler:           opts.Handler,
		ReadHeaderTimeout: opts.ReadHeaderTimeout,
		ReadTimeout:       opts.ReadTimeout,
		WriteTimeout:      opts.WriteTimeout,
		IdleTimeout:       opts.IdleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(opts.Logger.Handler(), slog.LevelWarn),
		// Requests keep the values of ctx but are not canceled with it, so
		// in-flight requests can complete during a graceful shutdown.
		BaseContext: func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	opts.Logger.LogAttrs(ctx, slog.LevelInfo, "http server listening",
		slog.String("address", ln.Addr().String()))

	select {
	case err := <-errc:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
	}

	opts.Logger.LogAttrs(ctx, slog.LevelInfo, "http server shutting down",
		slog.Duration("timeout", opts.ShutdownTimeout))
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opts.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		_ = srv.Close()
		return fmt.Errorf("http server shutdown: %w", err)
	}
	if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http server: %w", err)
	}
	opts.Logger.LogAttrs(ctx, slog.LevelInfo, "http server stopped")
	return nil
}
