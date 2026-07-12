package swu

import (
	"os"
	"strings"
	"testing"
)

func TestLoadCACertsSplitsBundle(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/bundle.pem"

	const certA = `-----BEGIN CERTIFICATE-----
MAAA
-----END CERTIFICATE-----
`
	const certB = `-----BEGIN CERTIFICATE-----
MBBB
-----END CERTIFICATE-----
`
	if err := os.WriteFile(path, []byte(certA+certB), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := loadCACerts([]string{path})
	if err != nil {
		t.Fatalf("loadCACerts: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d certs, want 2: %#v", len(got), got)
	}
	if !strings.Contains(got[0], "MAAA") || !strings.Contains(got[1], "MBBB") {
		t.Fatalf("split certs don't match expected content: %#v", got)
	}
	for _, c := range got {
		if !strings.HasPrefix(c, "-----BEGIN CERTIFICATE-----") {
			t.Fatalf("entry isn't a standalone PEM block: %q", c)
		}
	}
}

func TestLoadCACertsNoPEMIsError(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/notacert.txt"
	if err := os.WriteFile(path, []byte("not a cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadCACerts([]string{path}); err == nil {
		t.Fatal("expected an error for a file with no PEM certificates")
	}
}

func TestLoadCACertsMissingFileIsError(t *testing.T) {
	if _, err := loadCACerts([]string{"/nonexistent/path.pem"}); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

// TestLoadCACertsAgainstRealSystemBundle is a light integration check: it
// runs loadCACerts against whatever real system CA bundle this host
// actually has (skipping if none of the candidate paths exist), confirming
// the splitter handles a real, large, multi-certificate bundle -- not just
// the small synthetic fixture above -- and that every resulting entry
// parses as a well-formed single PEM certificate block.
func TestLoadCACertsAgainstRealSystemBundle(t *testing.T) {
	paths := systemCACertPathsForTest()
	if len(paths) == 0 {
		t.Skip("no system CA bundle found on this host")
	}

	got, err := loadCACerts(paths)
	if err != nil {
		t.Fatalf("loadCACerts(%v): %v", paths, err)
	}
	if len(got) < 2 {
		t.Fatalf("expected a real system bundle to split into multiple certs, got %d", len(got))
	}
	for i, c := range got {
		if strings.Count(c, "-----BEGIN CERTIFICATE-----") != 1 {
			t.Fatalf("entry %d isn't exactly one certificate block: %q", i, c)
		}
	}
	t.Logf("split real system CA bundle (%v) into %d individual certificates", paths, len(got))
}

// systemCACertPathsForTest mirrors runtimehost's systemCACertPaths without
// importing it (that would be an import cycle: runtimehost imports swu).
func systemCACertPathsForTest() []string {
	candidates := []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/etc/pki/tls/cacert.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/cert.pem",
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return []string{p}
		}
	}
	return nil
}
