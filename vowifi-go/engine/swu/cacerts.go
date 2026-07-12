package swu

import (
	"encoding/pem"
	"fmt"
	"os"
)

// loadCACerts reads each path in paths and returns one PEM-encoded string
// per individual certificate found in them, flattened.
//
// This exists because charon's vici cacerts field takes exactly one
// certificate per list entry -- confirmed by reading
// src/libcharon/plugins/vici/vici_config.c's parse_cacerts: each value goes
// straight into a single lib->creds->create(..., BUILD_BLOB_PEM, v, ...)
// call, which parses one certificate_t out of the blob and silently
// ignores anything after it. A system CA bundle (e.g.
// /etc/ssl/certs/ca-certificates.crt, ~130 concatenated certs) passed as
// one list entry would therefore load only its first certificate -- so
// paths are split here before ever reaching buildViciConn/the vici message,
// not left for charon to (fail to) do itself.
func loadCACerts(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("swu: read CA cert file %s: %w", path, err)
		}

		found := 0
		rest := data
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			out = append(out, string(pem.EncodeToMemory(block)))
			found++
		}
		if found == 0 {
			return nil, fmt.Errorf("swu: %s contains no PEM certificates", path)
		}
	}
	return out, nil
}
