package envscan

import (
	"testing"
)

func TestSkipDir_SharedExclusions(t *testing.T) {
	excluded := []string{
		".git", ".config", "node_modules", ".cache",
		".password-store", ".gnupg",
		"backup", ".env-backup-20260101",
	}
	for _, name := range excluded {
		if !SkipDir(name) {
			t.Errorf("SkipDir(%q) = false, want true", name)
		}
	}
	kept := []string{"proj", "src", "backup-old", ".env", "my-backup"}
	for _, name := range kept {
		if SkipDir(name) {
			t.Errorf("SkipDir(%q) = true, want false", name)
		}
	}
}

func TestIsEnvFile_ExactMatchOnly(t *testing.T) {
	if !IsEnvFile(".env") {
		t.Error(`IsEnvFile(".env") = false, want true`)
	}
	for _, name := range []string{".env.bak", "config.env", "a.env", ".ENV"} {
		if IsEnvFile(name) {
			t.Errorf("IsEnvFile(%q) = true, want false", name)
		}
	}
}

func TestParseEntries_KeepsQuotesVerbatim(t *testing.T) {
	data := []byte("A=1\n# comment\n\n  B =  two words  \nC=\n=no-key\nD\nE=\"quoted\"\n")
	got := map[string]string{}
	for _, e := range ParseEntries(data) {
		got[e.Key] = e.Value
	}
	want := map[string]string{
		"A": "1",
		"B": "two words",
		"C": "",
		"E": `"quoted"`, // quotes are preserved verbatim by contract
	}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("entry %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestContainsSecret_Patterns(t *testing.T) {
	patterns := []string{"API_KEY", "TOKEN", "SECRET", "PASSWORD"}
	if !ContainsSecret([]byte("API_KEY=dummy\n"), patterns) {
		t.Error("API_KEY line must match")
	}
	if ContainsSecret([]byte("# API_KEY=dummy\n"), patterns) {
		t.Error("comment line must not match")
	}
	if ContainsSecret([]byte("TIMEOUT=30\n"), patterns) {
		t.Error("unrelated line must not match")
	}
	if ContainsSecret([]byte(""), patterns) {
		t.Error("empty content must not match")
	}
}
