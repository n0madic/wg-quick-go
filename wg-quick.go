package main

import (
	"context"
	"fmt"
	"os"

	"github.com/n0madic/wg-quick-go/pkg/app"
)

func main() {
	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
