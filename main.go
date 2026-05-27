package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/chrj/diggity/cmd"
	"github.com/chrj/diggity/internal/check"
)

func main() {
	err := cmd.Execute()
	if err == nil {
		os.Exit(0)
	}

	var ce *check.ExitError
	if errors.As(err, &ce) {
		if ce.Err != nil {
			fmt.Fprintln(os.Stderr, "diggity:", ce.Err)
		}
		os.Exit(ce.Code)
	}

	fmt.Fprintln(os.Stderr, "diggity:", err)
	os.Exit(3)
}
