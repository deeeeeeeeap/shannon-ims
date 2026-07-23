package modem

import (
	"errors"
	"strings"
	"testing"
)

func TestATStreamParserRejectsLineBeyondLimitWithoutNewline(t *testing.T) {
	parser := newATStreamParser(16)

	lines, err := parser.Feed([]byte(strings.Repeat("A", 17)))

	if !errors.Is(err, ErrATLineTooLong) {
		t.Fatalf("Feed() error=%v, want ErrATLineTooLong", err)
	}
	if len(lines) != 0 {
		t.Fatalf("Feed() lines=%q, want none after overflow", lines)
	}
}

func TestATStreamParserRecognizesFragmentedPrompt(t *testing.T) {
	parser := newATStreamParser(16)

	lines, err := parser.Feed([]byte("\r\n>"))
	if err != nil {
		t.Fatalf("Feed(prompt prefix) error=%v", err)
	}
	if len(lines) != 1 || lines[0] != "> " {
		t.Fatalf("Feed(prompt prefix) lines=%q, want [\"> \"]", lines)
	}

	lines, err = parser.Feed([]byte(" "))
	if err != nil {
		t.Fatalf("Feed(prompt suffix) error=%v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("Feed(prompt suffix) lines=%q, want none", lines)
	}
}

func TestATStreamParserPreservesHalfLinesAcrossReads(t *testing.T) {
	parser := newATStreamParser(16)

	lines, err := parser.Feed([]byte("AT+CS"))
	if err != nil || len(lines) != 0 {
		t.Fatalf("Feed(first half) lines=%q error=%v, want no complete line", lines, err)
	}
	lines, err = parser.Feed([]byte("Q\r\nO"))
	if err != nil {
		t.Fatalf("Feed(second half) error=%v", err)
	}
	if len(lines) != 1 || lines[0] != "AT+CSQ" {
		t.Fatalf("Feed(second half) lines=%q, want [AT+CSQ]", lines)
	}
	lines, err = parser.Feed([]byte("K\r\n"))
	if err != nil {
		t.Fatalf("Feed(final half) error=%v", err)
	}
	if len(lines) != 1 || lines[0] != "OK" {
		t.Fatalf("Feed(final half) lines=%q, want [OK]", lines)
	}
}
