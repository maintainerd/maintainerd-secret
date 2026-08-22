package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
)

// Serving and shutdown.
//
// WHY THIS IS NOT kit's server.ServeHTTP / server.ServeGRPC. The kit helpers are the
// right default for an ordinary service, and this service used them until it needed two
// things they hardcode:
//
//   - CONFIGURABLE TIMEOUTS. kit fixes read at 15s, write at 60s, idle at 120s and the
//     shutdown drain at 15s. Every one of those is a bound on a resource an anonymous
//     peer can hold, and a vault's operator has to be able to set them for their
//     deployment — a 15s drain is too short for a node that has to finish in-flight
//     rewrap work, and a 15s read timeout is too long for a public edge.
//   - A READ-HEADER TIMEOUT AT ALL. kit sets ReadTimeout but not ReadHeaderTimeout, so a
//     slowloris client is bounded by the whole-request budget rather than by a
//     header-specific one. They are different attacks and want different numbers.
//
// The shutdown semantics below are otherwise the same as kit's, plus a hard bound: if
// the graceful drain does not finish within the timeout, the gRPC server is STOPPED
// rather than waited on, because a container runtime will send SIGKILL shortly after
// and an abrupt stop we chose is better than one the kernel chose.

// serveHTTP runs the REST surface until ctx is cancelled, then drains.
//
// The drain window belongs to in-flight REQUESTS. It is deliberately the same
// ShutdownTimeout the gRPC side uses and the rotator honours, so an operator sets one
// number and the whole process obeys it.
func serveHTTP(ctx context.Context, addr string, handler http.Handler, opts serverTimeouts) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: handler,
		// ReadHeaderTimeout is the slowloris bound specifically: it caps how long a
		// peer may take to send request headers, which is the phase that needs no
		// credential and produces no work.
		ReadHeaderTimeout: opts.ReadHeader,
		ReadTimeout:       opts.Read,
		WriteTimeout:      opts.Write,
		IdleTimeout:       opts.Idle,
		// MaxHeaderBytes bounds the header block. The default is 1 MiB, which is a
		// megabyte an unauthenticated peer can make the server allocate per connection.
		MaxHeaderBytes: 64 << 10,
		// The server's base context is the process context, so a handler that outlives
		// the signal sees a cancelled context rather than running on into the drain.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("http server listening", "addr", addr,
			"read_header_timeout", opts.ReadHeader.String(),
			"read_timeout", opts.Read.String(),
			"write_timeout", opts.Write.String(),
			"idle_timeout", opts.Idle.String())
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("draining http server", "addr", addr, "timeout", opts.Shutdown.String())
		// context.Background(), not ctx: ctx is already cancelled, and passing it
		// would make Shutdown return immediately without draining anything — the
		// classic graceful-shutdown bug.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), opts.Shutdown)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("http drain did not finish within the shutdown timeout; closing",
				"error", err)
			return srv.Close()
		}
		slog.Info("http server drained")
		return nil
	}
}

// serveGRPC runs the gRPC surface until ctx is cancelled, then drains.
//
// GracefulStop refuses new connections and waits for in-flight RPCs. It can wait
// forever on a stuck stream, so it runs on its own goroutine and is raced against the
// shutdown timeout; on expiry, Stop() severs the remaining connections.
func serveGRPC(ctx context.Context, addr string, gs *grpc.Server, shutdown time.Duration) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		slog.Info("draining grpc server", "addr", addr, "timeout", shutdown.String())
		drained := make(chan struct{})
		go func() {
			gs.GracefulStop()
			close(drained)
		}()
		select {
		case <-drained:
			slog.Info("grpc server drained")
		case <-time.After(shutdown):
			slog.Warn("grpc drain did not finish within the shutdown timeout; stopping abruptly",
				"timeout", shutdown.String())
			gs.Stop()
		}
	}()

	slog.Info("grpc server listening", "addr", addr)
	if err := gs.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// serverTimeouts groups the HTTP bounds so serveHTTP's signature does not grow a
// parameter every time one is added.
type serverTimeouts struct {
	ReadHeader time.Duration
	Read       time.Duration
	Write      time.Duration
	Idle       time.Duration
	Shutdown   time.Duration
}
