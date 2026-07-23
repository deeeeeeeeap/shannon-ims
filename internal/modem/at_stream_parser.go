package modem

import (
	"errors"
	"strings"
)

var (
	ErrATLineTooLong      = errors.New("AT response line exceeds limit")
	ErrATResponseTooLarge = errors.New("AT command response exceeds limit")
)

const (
	defaultATMaxLineBytes     = 64 << 10
	defaultATMaxResponseBytes = 1 << 20
)

type atStreamParser struct {
	maxLineBytes    int
	line            []byte
	overflowed      bool
	skipPromptSpace bool
}

func newATStreamParser(maxLineBytes int) *atStreamParser {
	if maxLineBytes <= 0 {
		maxLineBytes = 1
	}
	return &atStreamParser{
		maxLineBytes: maxLineBytes,
		line:         make([]byte, 0, min(maxLineBytes, 1024)),
	}
}

func (p *atStreamParser) Feed(data []byte) ([]string, error) {
	if p == nil || p.overflowed {
		return nil, ErrATLineTooLong
	}
	lines := make([]string, 0, 1)
	for _, b := range data {
		if p.skipPromptSpace {
			p.skipPromptSpace = false
			if b == ' ' {
				continue
			}
		}
		if b == '\n' {
			line := strings.TrimSpace(string(p.line))
			p.line = p.line[:0]
			if line != "" {
				lines = append(lines, line)
			}
			continue
		}
		if b == '>' && lineContainsOnlySpace(p.line) {
			p.line = p.line[:0]
			p.skipPromptSpace = true
			lines = append(lines, "> ")
			continue
		}
		if len(p.line) >= p.maxLineBytes {
			p.line = p.line[:0]
			p.overflowed = true
			return nil, ErrATLineTooLong
		}
		p.line = append(p.line, b)
	}
	return lines, nil
}

func lineContainsOnlySpace(line []byte) bool {
	for _, b := range line {
		switch b {
		case ' ', '\t', '\r':
		default:
			return false
		}
	}
	return true
}

func appendATResponseLine(lines *[]string, totalBytes *int, line string) error {
	if len(line) > defaultATMaxLineBytes {
		return ErrATLineTooLong
	}
	additional := len(line)
	if len(*lines) > 0 {
		additional++
	}
	if additional > defaultATMaxResponseBytes || *totalBytes > defaultATMaxResponseBytes-additional {
		return ErrATResponseTooLarge
	}
	*lines = append(*lines, line)
	*totalBytes += additional
	return nil
}
