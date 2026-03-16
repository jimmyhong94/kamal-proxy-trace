package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceparentMiddleware_GeneratesWhenNotPresent(t *testing.T) {
	handler := WithTraceparentMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp := r.Header.Get("Traceparent")
		assert.NotEmpty(t, tp)
		assert.Regexp(t, `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`, tp)
	}))

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTraceparentMiddleware_PreservesValidTraceparent(t *testing.T) {
	valid := "00-4bf92f3577b6a27ff4a0b22e1bf81c16-00f067aa0ba902b7-01"

	handler := WithTraceparentMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, valid, r.Header.Get("Traceparent"))
	}))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Traceparent", valid)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTraceparentMiddleware_ReplacesInvalidTraceparent(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"too short", "00-abc-def-01"},
		{"all-zero trace-id", "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
		{"all-zero parent-id", "00-4bf92f3577b6a27ff4a0b22e1bf81c16-0000000000000000-01"},
		{"uppercase hex", "00-4BF92F3577B6A27FF4A0B22E1BF81C16-00F067AA0BA902B7-01"},
		{"missing dashes", "004bf92f3577b6a27ff4a0b22e1bf81c1600f067aa0ba902b701"},
		{"empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := WithTraceparentMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tp := r.Header.Get("Traceparent")
				assert.NotEqual(t, tt.value, tp, "should replace invalid value")
				assert.Regexp(t, `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`, tp)
			}))

			r := httptest.NewRequest("GET", "/", nil)
			if tt.value != "" {
				r.Header.Set("Traceparent", tt.value)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestTraceparentMiddleware_GeneratesUniqueValues(t *testing.T) {
	seen := make(map[string]bool)
	middleware := &TraceparentMiddleware{}

	for i := 0; i < 100; i++ {
		tp := middleware.generateTraceparent()
		assert.False(t, seen[tp], "generated duplicate traceparent")
		seen[tp] = true
	}
}

func TestExtractTraceID(t *testing.T) {
	assert.Equal(t, "4bf92f3577b6a27ff4a0b22e1bf81c16", extractTraceID("00-4bf92f3577b6a27ff4a0b22e1bf81c16-00f067aa0ba902b7-01"))
	assert.Equal(t, "", extractTraceID(""))
	assert.Equal(t, "", extractTraceID("short"))
}
