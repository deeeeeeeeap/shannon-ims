package logger

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type redactingCore struct {
	zapcore.Core
}

func newRedactingCore(core zapcore.Core) zapcore.Core {
	return &redactingCore{Core: core}
}

func (c *redactingCore) With(fields []zapcore.Field) zapcore.Core {
	return &redactingCore{Core: c.Core.With(redactFields(fields))}
}

func (c *redactingCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if !c.Enabled(entry.Level) {
		return checked
	}
	return checked.AddCore(entry, c)
}

func (c *redactingCore) Write(entry zapcore.Entry, fields []zapcore.Field) error {
	entry.Message = RedactText(entry.Message)
	return c.Core.Write(entry, redactFields(fields))
}

func redactFields(fields []zapcore.Field) []zapcore.Field {
	if len(fields) == 0 {
		return fields
	}
	out := make([]zapcore.Field, 0, len(fields))
	for _, field := range fields {
		out = append(out, redactField(field))
	}
	return out
}

func redactField(field zapcore.Field) zapcore.Field {
	if field.Type == zapcore.NamespaceType {
		return field
	}
	value, ok := encodedFieldValue(field)
	if !ok {
		return field
	}

	switch classifySensitiveKey(field.Key) {
	case sensitiveOpaque:
		return zap.String(field.Key, "[REDACTED]")
	case sensitiveIdentity, sensitiveMaterial, sensitiveContent:
		return zap.String(field.Key, redactionSummary(field.Key, fieldValueText(value)))
	}

	switch typed := value.(type) {
	case string:
		return zap.String(field.Key, RedactText(typed))
	case error:
		return zap.String(field.Key, RedactText(typed.Error()))
	case []byte:
		return zap.String(field.Key, redactionSummary("binary", string(typed)))
	default:
		if field.Type == zapcore.ErrorType || field.Type == zapcore.StringerType {
			return zap.String(field.Key, RedactText(fmt.Sprint(value)))
		}
		if field.Type == zapcore.ReflectType ||
			field.Type == zapcore.ObjectMarshalerType ||
			field.Type == zapcore.ArrayMarshalerType {
			return zap.String(field.Key, redactionSummary("structured", fmt.Sprint(value)))
		}
		return field
	}
}

func encodedFieldValue(field zapcore.Field) (any, bool) {
	enc := zapcore.NewMapObjectEncoder()
	field.AddTo(enc)
	value, ok := enc.Fields[field.Key]
	return value, ok
}

func fieldValueText(value any) string {
	switch typed := value.(type) {
	case []byte:
		return string(typed)
	case error:
		return typed.Error()
	default:
		return fmt.Sprint(value)
	}
}

type sensitiveKeyKind uint8

const (
	sensitiveNone sensitiveKeyKind = iota
	sensitiveOpaque
	sensitiveIdentity
	sensitiveMaterial
	sensitiveContent
)

func classifySensitiveKey(key string) sensitiveKeyKind {
	key = normalizeLogKey(key)
	if key == "" || safeDiagnosticKey(key) {
		return sensitiveNone
	}
	parts := strings.Split(key, "_")
	if containsKeyPart(parts, "password", "token", "secret", "authorization", "cookie", "credential") ||
		key == "api_key" || key == "private_key" {
		return sensitiveOpaque
	}
	if containsKeyPart(parts, "rand", "autn", "auts", "res", "xres", "ck", "ik", "nonce", "kasme") {
		return sensitiveMaterial
	}
	if containsKeyPart(parts,
		"imei", "imsi", "iccid", "eid", "impi", "impu", "msisdn",
		"phone", "number", "sender", "recipient", "caller", "callee", "smsc",
		"peer", "identity", "subscriber", "username") || key == "call_id" {
		return sensitiveIdentity
	}
	switch key {
	case "content", "body", "pdu", "tpdu", "payload", "sip_raw", "raw_sip",
		"route", "request_uri", "destination", "contact", "from", "to":
		return sensitiveContent
	default:
		return sensitiveNone
	}
}

func normalizeLogKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(key)
}

func safeDiagnosticKey(key string) bool {
	for _, suffix := range []string{
		"_fingerprint", "_sha256", "_len", "_length", "_count", "_present",
		"_ready", "_round", "_status", "_total", "_index", "_changed", "_ms",
		"_seconds", "_duration", "_source", "_mode", "_kind", "_type", "_state",
	} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

func containsKeyPart(parts []string, candidates ...string) bool {
	for _, part := range parts {
		for _, candidate := range candidates {
			if part == candidate {
				return true
			}
		}
	}
	return false
}
