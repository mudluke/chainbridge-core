// Copyright 2021 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package cmd

import (
	evmCLI "github.com/ChainSafe/chainbridge-core/chains/evm/cli"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/local"
	"github.com/ChainSafe/chainbridge-core/example/app"
	"github.com/ChainSafe/chainbridge-core/flags"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	rootCMD = &cobra.Command{
		Use: "",
	}
	runCMD = &cobra.Command{
		Use:   "run",
		Short: "Run example app",
		Long:  "Run example app",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := app.Run(); err != nil {
				return err
			}
			return nil
		},
	}
)

var (
	accountCommand = &cobra.Command{
		Use:   "accounts",
		Short: "manage bridge keystore",
		Long: "The accounts command is used to manage the bridge keystore.\n" +
			"\tTo import a keystore file: chainbridge accounts import path/to/file\n" +
			"\tTo import a private key file: chainbridge accounts import --privateKey private_key\n",
	}

	importCmd = &cobra.Command{
		RunE:  wrapHandler(handleImportCmd),
		Use:   "import",
		Short: "import bridge keystore",
		Long: "The import subcommand is used to import a keystore for the bridge.\n" +
			"\tA path to the keystore must be provided\n" +
			"\tUse --privateKey to create a keystore from a provided private key.",
	}
)

func init() {
	flags.BindFlags(runCMD)

	importCmd.Flags().Bool("privateKey", false, "Prompt for a private key to import.")
	accountCommand.AddCommand(importCmd)
}

func Execute() {
	rootCMD.AddCommand(runCMD, evmCLI.EvmRootCLI, local.LocalSetupCmd)

	rootCMD.AddCommand(accountCommand)

	if err := rootCMD.Execute(); err != nil {
		log.Fatal().Err(err).Msg("failed to execute root cmd")
	}
}
