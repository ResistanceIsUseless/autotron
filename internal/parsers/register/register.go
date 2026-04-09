// Package register exists solely as a blank-import target that pulls in all
// parser files. Importing this package causes all parser init() functions
// to run, registering every parser with the global registry.
//
// Usage in cmd/asm/main.go:
//
//	import _ "github.com/resistanceisuseless/autotron/internal/parsers/register"
package register

import (
	// Pull in all parser files so their init() functions execute.
	_ "github.com/resistanceisuseless/autotron/internal/parsers"
)
