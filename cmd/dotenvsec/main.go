package main

import (
	"fmt"
	"os"

	"github.com/philband/dotenvsec/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "dotenvsec:", err)
		os.Exit(1)
	}
}
