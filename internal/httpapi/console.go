package httpapi

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"strings"
)

// Serving the console SPA from this process.
//
// THE IMAGE ALREADY PROMISED THIS AND COULD NOT DELIVER IT. The production image
// builds the SPA, bakes it at /srv/console and declares ENV CONSOLE_DIR — but nothing
// read that variable, so the contract was inert: the image shipped a UI it could not
// serve, and an operator had to put a second static host in front of it to see a
// console that was already inside the container.
//
// # CONSOLE_DIR AT RUNTIME, NOT go:embed
//
// maintainerd-auth compiles its SPAs INTO its binary (internal/webui, behind an
// `embedassets` build tag): the Docker build copies each dist/ into the Go source tree
// before compiling, and a build without the tag embeds nothing. That is the right
// answer for auth, which serves two SPAs on two dedicated ports and needs each one's
// API mounted same-origin so its __Host- prefixed cookies are returned.
//
// It is the wrong answer HERE, for three concrete reasons:
//
//	1. THE IMAGE CONTRACT ALREADY EXISTS AND IS RIGHT. /srv/console + CONSOLE_DIR is
//	   published, and the SPA's own settings are already read at RUNTIME from
//	   /srv/console/config.js (window.__ENV__) so one built image targets several
//	   deployments. Embedding would move the assets into the binary while leaving
//	   their configuration on disk — the awkward half of both models.
//	2. NO BUILD TAG, SO THE TESTED PATH IS THE SHIPPED PATH. An embed behind a tag is
//	   code `go test` never compiles: auth's traversal safety, cache headers and SPA
//	   fallback are exercised against a synthetic fs.FS, never against the thing the
//	   release actually serves. Reading a directory means the tests below drive the
//	   real resolver over a real directory, including the `../` payloads.
//	3. NO SOURCE-TREE MUTATION. Embedding requires the Docker build to copy dist/ into
//	   internal/ before compiling, which is a build that writes into its own source
//	   tree — and a `go build` in a worktree without that step silently produces a
//	   binary with an empty console.
//
// The cost of the runtime choice is that the directory must be present next to the
// binary. In the image it is, by construction; anywhere else CONSOLE_DIR is unset and
// the console is simply not served. Config refuses to boot when the variable points
// somewhere without an index.html, so "set but wrong" is a boot error rather than a
// site of 404s.
//
// # SAFETY
//
// The resolver is os.Root-based (Go's traversal-proof directory handle), so a path
// cannot escape the console directory even through a symlink — os.DirFS explicitly
// does not promise that, and "the file server is careful" is not a property worth
// resting a vault's process on. On top of it, every request path is cleaned and
// checked with fs.ValidPath before it is opened, and the handler REFUSES to serve
// anything under the API or probe prefixes even though routing means it should never
// see them.
//
// Nothing here is inside the guarded group. It is mounted as the router's NotFound
// handler, at the root, so it is outside the /api/v1 guard by construction — the same
// argument that puts /healthz outside it. Static assets are public by nature; the
// console holds no secret and obtains its own token in the browser.

// consoleHandler serves a built SPA from a directory.
type consoleHandler struct {
	// root is a traversal-proof handle on the console directory.
	root *os.Root
	// files is the standard file server over root, used for content types, ETags,
	// range requests and If-Modified-Since — none of which is worth reimplementing.
	files http.Handler
}

// newConsoleHandler opens dir and returns a handler over it, or nil when dir is empty.
//
// An error opening the directory is returned rather than swallowed: config has already
// verified the path, so a failure here is a real one (the directory vanished, or
// permissions changed) and starting up with a silently dead console is exactly the
// state this whole file exists to remove.
func newConsoleHandler(dir string) (*consoleHandler, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, nil
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &consoleHandler{root: root, files: http.FileServerFS(root.FS())}, nil
}

// reservedPrefixes are paths the console must never answer for, whatever the router
// does. They are checked here as well as being unreachable by routing, because the
// failure mode is bad in a specific way: an API client that mistypes a route would
// receive the SPA's index.html with a 200, and would parse HTML as JSON rather than
// see its 404.
var reservedPrefixes = []string{"/api/", "/healthz", "/readyz"}

func (h *consoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil {
		http.NotFound(w, r)
		return
	}
	// Only reads. A POST to an unknown path is not a deep link.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	for _, prefix := range reservedPrefixes {
		if r.URL.Path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(r.URL.Path, prefix) {
			// A JSON 404, not the SPA shell: this is an API path, and its client wants
			// a status it can branch on rather than a page it cannot parse.
			writeHealth(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
	}

	name := cleanConsolePath(r.URL.Path)
	if name == "" || !h.exists(name) {
		// Not a real asset — hand the SPA its shell so client-side routes resolve.
		// This is what makes a deep link like /browse/prod/db work on a hard refresh.
		h.serveIndex(w, r)
		return
	}

	// Hashed assets are immutable BY NAME: vite emits assets/index-<hash>.js, so a new
	// build produces a new URL and a cached copy of the old one can never be wrong. A
	// year with immutable is the whole point of content hashing.
	//
	// Everything else — index.html and, critically, config.js, which carries the
	// deployment's runtime settings — is no-store. A cached config.js is a console
	// pointed at the previous deployment's identity settings, which fails in a way
	// nobody attributes to a cache.
	if strings.HasPrefix(r.URL.Path, "/assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
	h.files.ServeHTTP(w, r)
}

// serveIndex writes the SPA shell with a 200, which is the correct answer for a
// client-side route: the resource the user asked for does exist, it is just resolved
// by the router in the page rather than by this server.
//
// It is served no-store. The shell names the hashed asset bundles, so a cached shell
// is a browser that keeps loading the PREVIOUS deployment's JavaScript — the classic
// "I deployed and nothing changed" bug, and on an OAuth client it can mean a token
// exchange against the wrong configuration.
func (h *consoleHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	f, err := h.root.Open("index.html")
	if err != nil {
		// Config proved index.html was readable at boot, so this means it has gone
		// since. It is not a reason to 500 the API: the console is unavailable, the
		// vault is not.
		writeHealth(w, http.StatusNotFound, map[string]any{"error": "the console is not available"})
		return
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		writeHealth(w, http.StatusNotFound, map[string]any{"error": "the console is not available"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// ServeContent sets Content-Length and handles HEAD and conditional requests; the
	// name is passed as index.html only so it does not have to sniff the type we just
	// set explicitly.
	http.ServeContent(w, r, "index.html", info.ModTime(), f)
}

// exists reports whether name is a readable FILE under the console root.
//
// Directories are deliberately NOT hits. A request for /assets would otherwise be
// answered with a file listing — a directory index of the deployment's asset names —
// where the SPA shell is both safer and more useful.
func (h *consoleHandler) exists(name string) bool {
	info, err := h.root.Stat(name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			// A permission or path-escape error is a miss, not a 500: the answer to
			// "can I serve this file" is no either way.
			return false
		}
		return false
	}
	return info.Mode().IsRegular()
}

// cleanConsolePath turns a URL path into a root-relative filesystem name, or "" when
// it is not one.
//
// THREE INDEPENDENT DEFENCES, and the reason there are three is that each covers a
// case the others do not:
//
//	path.Clean       resolves . and .. WITHIN the URL path, so "/a/../../etc/passwd"
//	                 collapses to "/etc/passwd" — no longer a traversal, just a path
//	                 that does not exist under the root.
//	fs.ValidPath     rejects anything still non-canonical after cleaning, plus any
//	                 remaining "..", any leading slash, and any empty element.
//	os.Root          refuses to open outside the directory AT THE SYSCALL, including
//	                 through a symlink, which is the case the two string checks above
//	                 cannot see.
//
// A path with a NUL byte is refused outright: it is never a real asset name, and it is
// the classic way to make a string check and a syscall disagree about where a path
// ends.
func cleanConsolePath(urlPath string) string {
	if urlPath == "" || strings.ContainsRune(urlPath, 0) {
		return ""
	}
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	cleaned := strings.TrimPrefix(path.Clean(urlPath), "/")
	if cleaned == "" || cleaned == "." {
		return ""
	}
	if !fs.ValidPath(cleaned) {
		return ""
	}
	return cleaned
}

// Close releases the directory handle. Called on shutdown; a nil handler is a no-op so
// callers need no branch.
func (h *consoleHandler) Close() error {
	if h == nil || h.root == nil {
		return nil
	}
	return h.root.Close()
}
