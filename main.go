package main

import (
	"log"
	"os"

	"github.com/ChainSafe/chainbridgev2/cmd"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:   "chainbridge",
		Usage:  "refactoring research",
		Action: cmd.Run,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
