package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hibiken/asynqmon"
)

// A responseRecorderWriter records response status and size.
// It implements http.ResponseWriter interface.
type responseRecorderWriter struct {
	http.ResponseWriter
	// The status code that the server sends back to the client.
	status int
	// The size of the object returned to the client, not including the response headers.
	size int
}

func (w *responseRecorderWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	w.status = status
}

func (w *responseRecorderWriter) Write(b []byte) (int, error) {
	// If WriteHeader is not called explicitly, the first call to Write
	// will trigger an implicit WriteHeader(http.StatusOK).
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.size += n
	return n, err
}

func loggingMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &responseRecorderWriter{ResponseWriter: w}
		h.ServeHTTP(rw, r)

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		username := "-"
		if user := r.URL.User; user != nil {
			username = user.Username()
		}
		size := "-"
		if rw.size > 0 {
			size = strconv.Itoa(rw.size)
		}
		// Write a log in Apache common log format (http://httpd.apache.org/docs/2.2/logs.html#common).
		fmt.Fprintf(os.Stdout, "%s - %s [%s] \"%s %s %s\" %d %s\n",
			host, username, time.Now().Format("02/Jan/2006:15:04:05 -0700"),
			r.Method, r.URL, r.Proto, rw.status, size)
	})
}

// Enable HTTP basic authentication if username:password is provided.
func basicAuth(h *asynqmon.HTTPHandler, auth string) http.Handler {
	if auth != "" {
		s := strings.Split(auth, ":")
		if len(s) == 2 {
			return http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					username, password, ok := r.BasicAuth()
					if ok {
						usernameHash := sha256.Sum256([]byte(username))
						passwordHash := sha256.Sum256([]byte(password))
						expectedUsernameHash := sha256.Sum256([]byte(s[0]))
						expectedPasswordHash := sha256.Sum256([]byte(s[1]))

						usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
						passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

						if usernameMatch && passwordMatch {
							h.ServeHTTP(w, r)
							return
						}
					}

					w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				},
			)
		}
	}
	return h
}
