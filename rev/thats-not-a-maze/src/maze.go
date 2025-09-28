package main

// Build with go build -gcflags="all=-N -l" -ldflags="-w"

import (
	"bigmaze/maze/gui"
)
func main() {
	gui.Start()
}