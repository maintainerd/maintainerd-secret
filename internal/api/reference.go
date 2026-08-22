package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/maintainerd/secret/internal/audit"
	"github.com/maintainerd/secret/internal/crypto"
	"github.com/maintainerd/secret/internal/platform/apperror"
	"github.com/maintainerd/secret/internal/platform/authz"
	"github.com/maintainerd/secret/internal/store"
)

// Secret references: a value of type `reference` is not a credential, it is a
// POINTER to one. Core's secret-typed template parameters resolve through this, and
// the agent's env-from-secret injection reads the resolved value at start without
// ever persisting it.
//
// THE SYNTAX is ${project/environment/folder/.../KEY}, embedded in text. A value may
// contain several placeholders and literal text around them, so
// "postgres://app:${billing/prod/db/PASSWORD}@db:5432/app" is a single reference
// value that renders to a working DSN. The environment is REQUIRED in the address —
// never implied from the referrer — because the same key exists once per environment
// and an implicit environment would make a reference copied from staging to prod mean
// something different in its new home while looking identical.
//
// A REFERENCE MUST NOT BECOME A PRIVILEGE-ESCALATION PATH. This is the property the
// whole file exists to hold. Without it, a principal granted reveal on
// secret/dev/* could write a reference in dev that points at
// secret/prod/db/PASSWORD, reveal its own dev secret, and receive prod's value —
// having never held a grant on prod. So secret:GetSecret is re-checked, against the
// TARGET's MRN, at EVERY hop, and every hop is separately audited. A caller's
// reachable set through references is therefore exactly its reachable set directly:
// references are a convenience for the authorized, never a bridge for the
// unauthorized.
//
// CYCLES are detected rather than merely bounded. A depth bound alone answers a
// cycle with "too deep", which sends an operator hunting for a long chain that does
// not exist; naming the loop turns a confusing timeout into a one-line fix. Both are
// implemented — the cycle check for accuracy, the depth bound as the backstop for a
// chain that is legitimately shaped but unreasonably long.

const (
	referenceOpen  = "${"
	referenceClose = "}"
)

// resolveReferences expands every placeholder in raw, following nested references.
//
// origin is the MRN of the value being expanded; it seeds the cycle chain so a
// secret that references itself is caught on the first hop rather than the second.
// Returns the rendered value and the ordered list of MRNs traversed.
func (s *Service) resolveReferences(ctx context.Context, c Caller, origin string, raw []byte) (crypto.Plaintext, []string, error) {
	chain := []string{origin}
	rendered, hops, err := s.expand(ctx, c, string(raw), chain, 0)
	if err != nil {
		return nil, nil, err
	}
	return crypto.Plaintext(rendered), hops, nil
}

// expand walks the template, resolving each placeholder.
//
// The accumulated result is a plain string builder rather than a crypto.Plaintext
// because it is being assembled from fragments; the caller converts once at the end.
// The intermediate is short-lived and never logged — the redaction guarantee that
// matters is on the types that cross a boundary.
func (s *Service) expand(ctx context.Context, c Caller, template string, chain []string, depth int) (string, []string, error) {
	if depth >= s.opts.ReferenceMaxDepth {
		return "", nil, apperror.NewValidation(fmt.Sprintf(
			"reference chain exceeded the maximum depth of %d: %s",
			s.opts.ReferenceMaxDepth, strings.Join(chain, " -> ")))
	}

	var out strings.Builder
	var hops []string
	rest := template

	for {
		start := strings.Index(rest, referenceOpen)
		if start < 0 {
			out.WriteString(rest)
			break
		}
		end := strings.Index(rest[start:], referenceClose)
		if end < 0 {
			// An unterminated placeholder is a malformed reference, not literal text.
			// Treating it as literal would silently hand a consumer the string
			// "${billing/prod/db/PASSWORD" as its database password.
			return "", nil, apperror.NewValidation("reference value contains an unterminated ${...} placeholder")
		}
		out.WriteString(rest[:start])
		addressText := rest[start+len(referenceOpen) : start+end]
		rest = rest[start+end+len(referenceClose):]

		value, hopMRNs, err := s.resolveOneReference(ctx, c, addressText, chain, depth)
		if err != nil {
			return "", nil, err
		}
		out.WriteString(value)
		hops = append(hops, hopMRNs...)
	}
	return out.String(), hops, nil
}

// resolveOneReference resolves a single ${...} address.
func (s *Service) resolveOneReference(ctx context.Context, c Caller, addressText string, chain []string, depth int) (string, []string, error) {
	project, environment, folderPath, key, ok := store.SplitReferencePath(addressText)
	if !ok {
		return "", nil, apperror.NewValidation(fmt.Sprintf(
			"reference %q must be project/environment[/folder...]/KEY", addressText))
	}
	ref := store.SecretRef{
		TenantUUID:  c.TenantUUID,
		Project:     project,
		Environment: environment,
		FolderPath:  folderPath,
		Key:         key,
	}
	targetMRN, err := s.store.SecretMRN(ctx, ref)
	if err != nil {
		return "", nil, err
	}

	// Cycle detection before anything else: a loop must not perform even one extra
	// decrypt, and the error names the whole path so the offending edge is obvious.
	for _, seen := range chain {
		if seen == targetMRN {
			return "", nil, apperror.NewValidation(fmt.Sprintf(
				"reference cycle detected: %s -> %s", strings.Join(chain, " -> "), targetMRN))
		}
	}

	// THE HOP PERMISSION CHECK. See the file comment: this is what keeps a reference
	// from being an escalation path. It is the same grant a direct reveal needs, on
	// the target's own MRN.
	if err := s.guard(ctx, c, authz.PermGetSecret, store.ActionReferenceResolve, targetMRN); err != nil {
		return "", nil, err
	}

	revealed, err := s.store.GetSecret(ctx, ref)
	if err != nil {
		s.recordFailure(ctx, c, store.ActionReferenceResolve, targetMRN, err)
		return "", nil, err
	}
	defer revealed.Zero()

	if err := s.recordSuccess(ctx, c, audit.Event{
		Action:      store.ActionReferenceResolve,
		ResourceMRN: targetMRN,
		SecretUUID:  &revealed.Meta.UUID,
		Version:     int32Ptr(revealed.Version),
		Metadata: map[string]any{
			"referrer":   chain[len(chain)-1],
			"hop":        depth + 1,
			"value_type": revealed.ValueType,
		},
	}); err != nil {
		return "", nil, err
	}

	hops := []string{targetMRN}
	if revealed.ValueType != store.ValueTypeReference {
		return string(revealed.Value.Bytes()), hops, nil
	}
	// The target is itself a reference: recurse with the chain extended, which is
	// what makes the cycle check transitive.
	// The chain is COPIED rather than appended in place. Two placeholders in one
	// template share the caller's slice, and an in-place append would have each
	// sibling write over the other's tail — harmless today because the recursion has
	// returned by then, and a genuinely confusing bug the first time this loop is
	// made concurrent.
	extended := make([]string, len(chain), len(chain)+1)
	copy(extended, chain)
	extended = append(extended, targetMRN)
	nested, nestedHops, err := s.expand(ctx, c, string(revealed.Value.Bytes()), extended, depth+1)
	if err != nil {
		return "", nil, err
	}
	return nested, append(hops, nestedHops...), nil
}
