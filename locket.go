package locket

import (
	"log/slog"
	"testing"
)

// type source string

// var (
// 	SourceEnv  source = "env"  // environment vars
// 	SourceOp   source = "op"   // 1password
// 	SourceFile source = "file" // file
// )

// kvRequest contains

type kvResponse struct {
	Payload string `json:"payload"`
}

func init() {
	if testing.Testing() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}
}
