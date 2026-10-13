package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

func options(h http.Handler, shutdown time.Duration) Options {
	return Options{
		Handler:           h,
		Logger:            slog.New(slog.DiscardHandler),
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		ShutdownTimeout:   shutdown,
	}
}

func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func TestServeCompletesInFlightRequestsOnShutdown(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(w, "done")
	})

	ln := listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, ln, options(h, 5*time.Second)) }()

	type result struct {
		body string
		err  error
	}
	resc := make(chan result, 1)
	go func() {
		resp, err := get(t.Context(), "http://"+ln.Addr().String()+"/")
		if err != nil {
			resc <- result{err: err}
			return
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		resc <- result{body: string(b), err: err}
	}()

	<-started
	cancel()
	close(release)

	res := <-resc
	if res.err != nil || res.body != "done" {
		t.Errorf("in-flight request = (%q, %v), want (\"done\", nil)", res.body, res.err)
	}
	if err := <-served; err != nil {
		t.Errorf("Serve() = %v, want nil after a clean shutdown", err)
	}
}

func TestServeReturnsErrorWhenShutdownTimesOut(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		close(started)
		<-release
	})

	ln := listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, ln, options(h, time.Millisecond)) }()

	go func() {
		resp, err := get(t.Context(), "http://"+ln.Addr().String()+"/")
		if err == nil {
			resp.Body.Close()
		}
	}()

	<-started
	cancel()
	if err := <-served; !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Serve() = %v, want context.DeadlineExceeded", err)
	}
}

func TestServeReturnsListenerErrors(t *testing.T) {
	t.Parallel()

	ln := listen(t)
	if err := ln.Close(); err != nil {
		t.Fatalf("closing listener: %v", err)
	}
	err := Serve(t.Context(), ln, options(http.NotFoundHandler(), time.Second))
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve() = %v, want net.ErrClosed", err)
	}
}
