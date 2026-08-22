package grpcserver

import (
	"context"
	"net"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	sdkauthz "github.com/maintainerd/sdk/authz"

	"github.com/maintainerd/secret/internal/platform/permissions"
)

// THE AUTH INTERCEPTOR IS THE SDK'S, NOT THIS PACKAGE'S.
//
// This file used to carry a hand-rolled copy: a method→permission map, a bearer
// extractor, a mode ladder and a deny-by-default switch. All of that now lives in
// github.com/maintainerd/sdk/authz, shared with every other maintainerd service
// and with third-party resource servers built beside them, and the only thing
// that stayed behind is this service's own VOCABULARY — which moved to
// internal/platform/permissions as one authz.Map literal. The map still doubles
// as the surface allowlist, so registering an RPC without deciding its permission
// still fails closed; it is just no longer this repo's job to implement that.
//
// TWO INTERCEPTORS ARE RETURNED, AND BOTH ARE REQUIRED. grpc-go dispatches unary
// and streaming calls through different chains, so a server that installs only a
// UnaryServerInterceptor leaves every server-streaming and bidi RPC completely
// unguarded — no token check, no permission check, no allowlist. There is no
// streaming RPC in maintainerd.secret.v1 today, which is exactly why that hole
// was invisible; installing the stream interceptor now means the first streaming
// RPC anybody adds arrives guarded rather than open.

// The gRPC service prefixes, re-exported from the permission table so the
// allowlist, the rate limiter and the handlers cannot disagree about what a
// method is called.
const (
	secretService           = permissions.SecretServicePrefix
	setupServicePrefix      = permissions.SetupServicePrefix
	healthServicePrefix     = permissions.HealthServicePrefix
	reflectionServicePrefix = permissions.ReflectionServicePrefix
)

// AuthUnaryInterceptor enforces authentication and per-method permissions on
// unary RPCs, through the SDK guard.
//
// Fail-closed by construction, all of it decided in authz.Guard.Check:
//
//	no token           -> Unauthenticated
//	invalid token      -> Unauthenticated (never echoing WHY — that is oracle material)
//	method not mapped  -> PermissionDenied (unknown surface, deny)
//	permission missing -> PermissionDenied
//	auth unconfigured  -> Unavailable, outside development
//
// Exempt methods — health, Ping, and the two self-guarded setup surfaces — are
// let through with no principal attached; permissions.Map carries the argument
// for each one. Server reflection is deliberately NEITHER mapped NOR exempt, so
// it is denied by the allowlist under ModeEnforced and reachable only under
// ModeDevOpen, where the guard admits every caller before it consults the map.
// That is the same development-only posture the hand-rolled interceptor had, and
// the bootstrap additionally registers the reflection service only in
// development, so outside it there is nothing behind the door either.
func AuthUnaryInterceptor(guard sdkauthz.Guard) grpc.UnaryServerInterceptor {
	return guard.UnaryInterceptor()
}

// AuthStreamInterceptor is the same decision path for streaming RPCs, carrying
// the verified principal into the stream handler's context. It is not optional —
// see the note at the top of this file.
func AuthStreamInterceptor(guard sdkauthz.Guard) grpc.StreamServerInterceptor {
	return guard.StreamInterceptor()
}

// MappedMethods returns every RPC the guard demands a permission for, sorted. It
// exists so a test can assert the allowlist covers the whole registered surface:
// an allowlist only fails closed if it is actually complete, and a method missing
// from it is a 403 nobody can explain.
func MappedMethods() []string {
	m := permissions.Map()
	out := make([]string, 0, len(m.Methods))
	for method := range m.Methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

// bearerFromMD extracts a "Bearer <token>" authorization header from the incoming
// gRPC metadata, delegating to the SDK's parser so the guard and anything else
// that inspects a call read the header identically.
func bearerFromMD(ctx context.Context) string {
	return sdkauthz.BearerFromMetadata(ctx)
}

// metadataValue reads the first value of a metadata key.
func metadataValue(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(key)
	if len(vals) == 0 {
		return ""
	}
	return strings.TrimSpace(vals[0])
}

// peerIP returns the caller's address with the port stripped.
//
// As on the HTTP side, a caller-supplied forwarded-for value is NOT consulted:
// letting a client choose what lands in this service's audit trail would turn the
// field an incident review depends on into one an attacker writes.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}
