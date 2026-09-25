package main

import (
	"strings"
	"testing"
)

// The convention is worth a test because it is the part of the CLI an
// operator gets wrong first: verbs that act on the daemon are bare,
// everything else carries the dashes.
func TestServiceVerbsAreBare(t *testing.T) {
	for verb := range serviceVerbs {
		got, err := normalizeCommand(verb)
		if err != nil {
			t.Errorf("%q was refused: %v", verb, err)
			continue
		}
		if got != verb {
			t.Errorf("normalizeCommand(%q) = %q", verb, got)
		}

		_, err = normalizeCommand("--" + verb)
		if err == nil {
			t.Errorf("--%s was accepted, service verbs take no dashes", verb)
			continue
		}
		if !strings.Contains(err.Error(), verb) {
			t.Errorf("the error for --%s does not show the right spelling: %v", verb, err)
		}
	}
}

func TestEverythingElseRequiresDashes(t *testing.T) {
	for cmd := range flagCommands {
		got, err := normalizeCommand("--" + cmd)
		if err != nil {
			t.Errorf("--%s was refused: %v", cmd, err)
			continue
		}
		if got != cmd {
			t.Errorf("normalizeCommand(--%s) = %q", cmd, got)
		}

		_, err = normalizeCommand(cmd)
		if err == nil {
			t.Errorf("%q was accepted without dashes", cmd)
			continue
		}
		if !strings.Contains(err.Error(), "--"+cmd) {
			t.Errorf("the error for %q does not show the right spelling: %v", cmd, err)
		}
	}
}

func TestObjectCommandsAreBare(t *testing.T) {
	for cmd := range objectCommands {
		if got, err := normalizeCommand(cmd); err != nil || got != cmd {
			t.Errorf("normalizeCommand(%q) = %q, %v", cmd, got, err)
		}
		if _, err := normalizeCommand("--" + cmd); err == nil {
			t.Errorf("--%s was accepted, object commands take no dashes", cmd)
		}
	}
}

func TestUnknownCommandIsRejected(t *testing.T) {
	for _, cmd := range []string{"", "--apply", "-status", "hosts", "-host", "applyy"} {
		if _, err := normalizeCommand(cmd); err == nil {
			t.Errorf("%q was accepted", cmd)
		}
	}
}
