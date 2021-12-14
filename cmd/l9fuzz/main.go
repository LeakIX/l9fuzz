package main

import (
	"github.com/LeakIX/l9fuzz"
	"github.com/alecthomas/kong"
	"io"
)

var App struct {
	Scan l9l4gfuzz.Scanner `cmd help:"Scans url for JNDI"`
}

func main() {
	ctx := kong.Parse(&App)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run()
	if err != io.EOF {
		ctx.FatalIfErrorf(err)
	}
}
