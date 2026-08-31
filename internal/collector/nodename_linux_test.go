//go:build linux

package collector

import "testing"

func TestReadNodeName(t *testing.T) {
	nodeName, err := readNodeName()
	if err != nil {
		t.Fatal(err)
	}
	if nodeName == "" {
		t.Fatal("read an empty node name")
	}
}
