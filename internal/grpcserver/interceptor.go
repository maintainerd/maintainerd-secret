package grpcserver

import (
	"context"
	"net"
	"sort"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/maintainerd/secret/internal/platform/authz"
)

// The gRPC twin of the HTTP guard (internal/platform/authz), mirroring
// maintainerd-agent's interceptor: a method→permission map that DOUBLES AS THE
// SURFACE ALLOWLIST, so adding an RPC to the proto without deciding its permission
// fails closed instead of shipping an unguarded endpoint.
//
// As on the HTTP side, the map is the BASELINE and the surface allowlist — not the
// authorization decision. The real check is MRN-level and happens inside the api
// service, because the target's MRN is not knowable from the method name.

// methodPermissions maps every RPC to the permission its caller must carry. An empty
// value means "any authenticated principal": identity proven, no extra grant.
//
// A method that is NOT listed here is DENIED.
var methodPermissions = map[string]string{
	// Legacy flat-key surface — the kit secret-provider client's contract. The
	// permissions are the real ones for the operation, not a compatibility
	// exemption: an old client with a token that cannot read secrets could never
	// read them through the old RPC either.
	secretService + "Put":    authz.PermPutSecret,
	secretService + "Get":    authz.PermGetSecret,
	secretService + "List":   authz.PermListSecrets,
	secretService + "Delete": authz.PermDeleteSecret,

	// Projects / environments / folders / imports.
	secretService + "CreateProject":     authz.PermManageProject,
	secretService + "ListProjects":      authz.PermReadMetadata,
	secretService + "GetProject":        authz.PermReadMetadata,
	secretService + "UpdateProject":     authz.PermManageProject,
	secretService + "DeleteProject":     authz.PermManageProject,
	secretService + "CreateEnvironment": authz.PermManageEnvironment,
	secretService + "ListEnvironments":  authz.PermReadMetadata,
	secretService + "GetEnvironment":    authz.PermReadMetadata,
	secretService + "UpdateEnvironment": authz.PermManageEnvironment,
	secretService + "DeleteEnvironment": authz.PermManageEnvironment,
	secretService + "CreateFolder":      authz.PermManageFolder,
	secretService + "ListFolders":       authz.PermReadMetadata,
	secretService + "MoveFolder":        authz.PermManageFolder,
	secretService + "DeleteFolder":      authz.PermManageFolder,
	secretService + "CreateImport":      authz.PermManageFolder,
	secretService + "ListImports":       authz.PermReadMetadata,
	secretService + "UpdateImport":      authz.PermManageFolder,
	secretService + "DeleteImport":      authz.PermManageFolder,

	// Secrets. GetSecret is the reveal and carries the reveal permission; every
	// metadata operation carries the metadata one. The distinction is the point.
	secretService + "GetSecret":            authz.PermGetSecret,
	secretService + "DescribeSecret":       authz.PermReadMetadata,
	secretService + "ListSecrets":          authz.PermListSecrets,
	secretService + "PutSecret":            authz.PermPutSecret,
	secretService + "UpdateSecretMetadata": authz.PermPutSecret,
	secretService + "ListSecretVersions":   authz.PermReadMetadata,
	secretService + "RollbackSecret":       authz.PermPutSecret,
	secretService + "RotateSecret":         authz.PermRotateSecret,
	secretService + "SetRotationPolicy":    authz.PermManageRotation,
	secretService + "DeleteSecret":         authz.PermDeleteSecret,
	secretService + "ListDeletedSecrets":   authz.PermListSecrets,
	secretService + "RestoreSecret":        authz.PermDeleteSecret,
	secretService + "DestroySecret":        authz.PermDeleteSecret,

	// Bulk. The baseline is metadata because a batch mixes items whose individual
	// privileges differ; each item is checked with the operation's real permission
	// against its own MRN inside the api service.
	secretService + "BatchGetSecrets": authz.PermReadMetadata,
	secretService + "BatchPutSecrets": authz.PermReadMetadata,

	// Webhooks + audit.
	secretService + "CreateWebhookEndpoint": authz.PermManageRotation,
	secretService + "ListWebhookEndpoints":  authz.PermReadMetadata,
	secretService + "UpdateWebhookEndpoint": authz.PermManageRotation,
	secretService + "DeleteWebhookEndpoint": authz.PermManageRotation,
	secretService + "ListWebhookDeliveries": authz.PermReadMetadata,
	secretService + "ListAuditEvents":       authz.PermReadAudit,
}

const secretService = "/maintainerd.secret.v1.SecretService/"

// selfGuardedMethods bypass the BEARER requirement because they must work before
// Auth exists, and they carry their own gate instead:
//
//	Ping   answers {ok, setup_complete} and nothing else — the same single bit the
//	       anonymous REST setup status returns. An orchestrator has to be able to
//	       ask "is this instance provisioned yet" before it has provisioned the
//	       thing that mints tokens.
//	Setup  (the legacy flat-surface RPC) is gated by the bootstrap token, compared
//	       in constant time inside the handler.
//
// Nothing else may be added here without the same argument: a method on this list
// is a method no token protects.
var selfGuardedMethods = map[string]bool{
	secretService + "Ping":  true,
	secretService + "Setup": true,
}

// setupServicePrefix is the CONTROLLED setup surface. It is self-guarded by the
// x-setup-token metadata header for the same reason the REST wizard is: it is what
// provisions the instance, so it cannot require a token only a provisioned instance
// can mint.
const setupServicePrefix = "/maintainerd.secret.v1.SetupService/"

// healthServicePrefix is the ONLY wholly unauthenticated surface: the standard
// health protocol. Orchestrators and load balancers must probe liveness before they
// have credentials, and the response leaks nothing beyond "serving".
const healthServicePrefix = "/grpc.health.v1.Health/"

// reflectionServicePrefix is gated on development. Reflection enumerates every RPC
// and message in the service — a map of the vault's API handed to anyone who can
// open a socket. Useful with grpcurl on a laptop, reconnaissance in production.
const reflectionServicePrefix = "/grpc.reflection."

// AuthUnaryInterceptor enforces authentication and per-method permissions.
//
// Fail-closed by construction:
//
//	no token           -> Unauthenticated
//	invalid token      -> Unauthenticated (never echoing WHY — that is oracle material)
//	method not mapped  -> PermissionDenied (unknown surface, deny)
//	permission missing -> PermissionDenied
//	auth unconfigured  -> Unavailable, outside development
func AuthUnaryInterceptor(guard authz.Guard) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		method := info.FullMethod
		switch {
		case strings.HasPrefix(method, healthServicePrefix):
			return handler(ctx, req)
		case strings.HasPrefix(method, reflectionServicePrefix):
			if guard.Mode != authz.ModeDevOpen {
				return nil, status.Error(codes.PermissionDenied, "server reflection is available only in development")
			}
			return handler(ctx, req)
		case strings.HasPrefix(method, setupServicePrefix), selfGuardedMethods[method]:
			// Self-guarded: the handler checks the setup/bootstrap token itself.
			return handler(ctx, req)
		}

		switch guard.Mode {
		case authz.ModeDevOpen:
			return handler(authz.NewContext(ctx, authz.DevClaims()), req)
		case authz.ModeUnavailable:
			return nil, status.Errorf(codes.Unavailable,
				"API authentication is not configured (%s); the API is disabled outside development", guard.Reason)
		}

		token := bearerFromMD(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		claims, err := guard.Verify(ctx, token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}
		required, known := methodPermissions[method]
		if !known {
			return nil, status.Errorf(codes.PermissionDenied, "method %s has no permission mapping", method)
		}
		if required != "" && !claims.HasAction(required) {
			return nil, status.Errorf(codes.PermissionDenied, "requires permission %s", required)
		}
		return handler(authz.NewContext(ctx, claims), req)
	}
}

// MappedMethods returns every RPC the interceptor guards, sorted. It exists so a
// test can assert the map covers the whole registered surface: the allowlist only
// fails closed if it is actually complete, and a method missing from it is a 403
// nobody can explain.
func MappedMethods() []string {
	out := make([]string, 0, len(methodPermissions))
	for m := range methodPermissions {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// bearerFromMD extracts a "Bearer <token>" authorization header from the incoming
// gRPC metadata.
func bearerFromMD(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	header := vals[0]
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return ""
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
