package logx

import (
	"bytes"
	"log"
	"log/slog"
	"regexp"
	"testing"
)

func TestPlainFormatMatchesOldLogStyle(t *testing.T) {
	var buf bytes.Buffer
	InitWriter(&buf, slog.LevelInfo)
	For("warp").Infof("connected via %s", "1.2.3.4:2408")
	For("").Infof("Club Connect v%s", "0.8")
	For("psiphon").Info("tunnel established", "level", 1, "note", "two words")
	want := regexp.MustCompile(`^\d\d:\d\d:\d\d \[warp\] connected via 1\.2\.3\.4:2408\n` +
		`\d\d:\d\d:\d\d Club Connect v1\.8\n` +
		`\d\d:\d\d:\d\d \[psiphon\] tunnel established level=1 note="two words"\n$`)
	if !want.Match(buf.Bytes()) {
		t.Fatalf("unexpected output:\n%s", buf.String())
	}
}

func TestStdlibLogGoesThroughHandler(t *testing.T) {
	var buf bytes.Buffer
	InitWriter(&buf, slog.LevelInfo)
	log.Printf("hello %d", 8)
	if !regexp.MustCompile(`^\d\d:\d\d:\d\d hello 8\n$`).Match(buf.Bytes()) {
		t.Fatalf("stdlib log line: %q", buf.String())
	}
}

func TestLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	InitWriter(&buf, slog.LevelError)
	For("x").Infof("hidden")
	For("x").Errorf("shown")
	if !regexp.MustCompile(`^\d\d:\d\d:\d\d \[x\] shown\n$`).Match(buf.Bytes()) {
		t.Fatalf("level filter: %q", buf.String())
	}
}
