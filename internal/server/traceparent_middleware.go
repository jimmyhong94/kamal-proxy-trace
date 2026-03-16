package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

const (
	traceparentHeader = "Traceparent"
)

type TraceparentMiddleware struct {
	next http.Handler
}

func WithTraceparentMiddleware(next http.Handler) http.Handler {
	return &TraceparentMiddleware{
		next: next,
	}
}

func (h *TraceparentMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isValidTraceparent(r.Header.Get(traceparentHeader)) {
		r.Header.Set(traceparentHeader, h.generateTraceparent())
	}
	h.next.ServeHTTP(w, r)
}

func (h *TraceparentMiddleware) generateTraceparent() string {
	traceID := make([]byte, 16)
	parentID := make([]byte, 8)
	rand.Read(traceID)
	rand.Read(parentID)
	return "00-" + hex.EncodeToString(traceID) + "-" + hex.EncodeToString(parentID) + "-01"
}

// isValidTraceparent checks whether a traceparent header value conforms to the
// W3C Trace Context format: {version}-{trace-id}-{parent-id}-{trace-flags}.
// It accepts any version but validates that the trace-id and parent-id segments
// are well-formed hex and not all zeros.
func isValidTraceparent(value string) bool {
	if len(value) < 55 {
		return false
	}
	if value[2] != '-' || value[35] != '-' || value[52] != '-' {
		return false
	}

	traceID := value[3:35]
	if !isLowercaseHex(traceID) || traceID == "00000000000000000000000000000000" {
		return false
	}

	parentID := value[36:52]
	if !isLowercaseHex(parentID) || parentID == "0000000000000000" {
		return false
	}

	return true
}

func isLowercaseHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// extractTraceID returns the 32-character trace-id portion of a valid
// traceparent header value, or an empty string if the header is absent
// or malformed.
func extractTraceID(traceparent string) string {
	if len(traceparent) >= 35 && traceparent[2] == '-' {
		return traceparent[3:35]
	}
	return ""
}
