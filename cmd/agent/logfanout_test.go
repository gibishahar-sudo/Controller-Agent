package main

import (
	"errors"
	"io"
	"testing"
)

type errWriter struct{ err error }

func (e errWriter) Write(p []byte) (int, error) { return 0, e.err }

type sinkWriter struct{ got []byte }

func (s *sinkWriter) Write(p []byte) (int, error) {
	s.got = append(s.got, p...)
	return len(p), nil
}

// One wedged target must not silence the rest.
func TestFanoutSurvivesBadTarget(t *testing.T) {
	bad := errWriter{err: errors.New("disk wedged")}
	good := &sinkWriter{}
	fw := &fanoutWriter{ws: []io.Writer{bad, good}}
	if _, err := fw.Write([]byte("hello")); err == nil {
		t.Fatal("expected the wedged error to surface")
	}
	if string(good.got) != "hello" {
		t.Fatalf("good target got %q, want hello", good.got)
	}
}
