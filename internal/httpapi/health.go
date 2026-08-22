package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/maintainerd/secret/internal/platform/response"
)

// The health probes, and the reason there are two of them.
//
// LIVENESS (/healthz) ANSWERS ONE QUESTION: is this process still able to serve? It
// touches nothing — no database, no JWKS, no disk. That is not laziness, it is the
// contract: an orchestrator RESTARTS a container whose liveness probe fails, so a
// liveness probe that depends on Postgres turns a database blip into a rolling restart
// of every replica, which is the textbook way to convert a recoverable incident into an
// outage. The only correct failure mode for this endpoint is "the process is wedged".
//
// READINESS (/readyz) ANSWERS A DIFFERENT ONE: should this replica receive traffic
// right now? It probes the dependencies an actual request needs, and it FAILS CLOSED —
// while the database is unreachable or the JWKS has not loaded, this replica reports
// not-ready and the load balancer stops sending it work. For a vault the fail-closed
// direction is the only defensible one: a replica that cannot verify tokens must not be
// answering, and a replica that cannot reach its store can only produce errors.
//
// NEITHER PROBE IS AUTHENTICATED, and both are mounted outside /api/v1 so that is true
// by construction. What they disclose is bounded on purpose: liveness says "ok", and
// readiness says which named dependency is unhealthy — a dependency NAME ("database",
// "jwks"), never an address, a driver message or a version. An orchestrator has to be
// able to probe before it holds a credential; an attacker learns that this service has
// a database, which they could have guessed.

// healthz is the liveness probe. Cheap, dependency-free, always 200 while the process
// is scheduling goroutines.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeHealth(w, http.StatusOK, map[string]any{"status": "ok"})
}

// readyz is the readiness probe. It runs every configured check concurrently under one
// bounded context and answers 200 only if all of them pass.
//
// The checks run CONCURRENTLY and share one deadline, so the endpoint's worst-case
// latency is the timeout rather than the sum of the probes. A probe that ignores its
// context is reported as failing when the deadline passes rather than being waited on:
// a readiness endpoint that hangs is read as healthy by some orchestrators and unhealthy
// by others, which is the one answer worse than either.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.opts.ReadinessTimeout)
	defer cancel()

	type result struct {
		name string
		err  error
	}
	results := make([]result, len(s.opts.Readiness))

	var wg sync.WaitGroup
	for i, check := range s.opts.Readiness {
		results[i].name = check.Name
		if check.Probe == nil {
			continue
		}
		wg.Add(1)
		go func(i int, probe func(context.Context) error) {
			defer wg.Done()
			done := make(chan error, 1)
			go func() { done <- probe(ctx) }()
			select {
			case err := <-done:
				results[i].err = err
			case <-ctx.Done():
				results[i].err = ctx.Err()
			}
		}(i, check.Probe)
	}
	wg.Wait()

	checks := make(map[string]string, len(results))
	ready := true
	for _, res := range results {
		if res.err != nil {
			ready = false
			checks[res.name] = "unhealthy"
			// The CAUSE goes to the server log, never to the response: a driver error
			// names hosts, databases and sometimes users.
			response.LoggerFromContext(r.Context()).Warn("readiness check failed",
				"check", res.name, "error", res.err)
			continue
		}
		checks[res.name] = "ok"
	}

	status := http.StatusOK
	body := map[string]any{"status": "ready", "checks": checks}
	if !ready {
		status = http.StatusServiceUnavailable
		body["status"] = "not_ready"
	}
	writeHealth(w, status, body)
}

// writeHealth writes a probe response.
//
// It bypasses the response envelope deliberately. An orchestrator's probe parser is
// configured once and never revisited, so the health payload is its own tiny, stable
// contract rather than something that moves when the API envelope does.
func writeHealth(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
