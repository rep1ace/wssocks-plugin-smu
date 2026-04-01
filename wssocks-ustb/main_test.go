package main

import (
	"errors"
	"testing"

	"github.com/rep1ace/wssocks/client"
	"github.com/rep1ace/wssocks-plugin-smu/extra"
)

func TestStartWssocksDoesNotReregisterPlugins(t *testing.T) {
	handles := &extra.TaskHandles{}

	err := handles.StartWssocks(extra.Options{})
	if errors.Is(err, client.ErrPluginOccupied) {
		t.Fatal("StartWssocks re-registered an already-installed plugin")
	}
	if err == nil || err.Error() != "empty remote address" {
		t.Fatalf("expected empty remote address error after plugin setup, got %v", err)
	}
}
