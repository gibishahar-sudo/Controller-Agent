//go:build windows

package main

import (
	"reflect"
	"testing"
)

func TestParseMpList(t *testing.T) {
	got := parseMpList("C:\\A\r\n\r\n  C:\\B  \n\n")
	if !reflect.DeepEqual(got, []string{`C:\A`, `C:\B`}) {
		t.Fatalf("got %q", got)
	}
	if len(parseMpList("")) != 0 {
		t.Fatal("empty should parse empty")
	}
}

func TestMpListHas(t *testing.T) {
	have := []string{`C:\ProgramData\Microsoft\Windows\Update`, `C:\X\Agent.exe`}
	if !mpListHas(have, `c:\programdata\microsoft\windows\update\`) {
		t.Fatal("case/trailing-slash should match")
	}
	if mpListHas(have, `C:\Nope`) {
		t.Fatal("absent must not match")
	}
	if mpListHas(nil, `C:\X`) {
		t.Fatal("nil must not match")
	}
}
