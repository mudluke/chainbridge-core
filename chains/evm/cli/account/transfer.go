package account

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls"
	"github.com/ChainSafe/chainbridge-core/chains/evm/cli/flags"
	"github.com/ChainSafe/chainbridge-core/chains/evm/evmclient"
	"github.com/ChainSafe/chainbridge-core/chains/evm/evmtransaction"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var transferBaseCurrencyCmd = &cobra.Command{
	Use:    "transfer",
	Short:  "Transfer base currency",
	Long:   "The generate subcommand is used to transfer the base currency",
	PreRun: confirmTransfer,
	RunE: func(cmd *cobra.Command, args []string) error {
		txFabric := evmtransaction.NewTransaction
		return transferBaseCurrency(cmd, args, txFabric)
	},
	Args: func(cmd *cobra.Command, args []string) error {
		err := validateTransferBaseCurrencyFlags(cmd, args)
		if err != nil {
			return err
		}

		err = processTransferBaseCurrencyFlags(cmd, args)
		return err
	},
}

func BindTransferCmdFlags() {
	transferBaseCurrencyCmd.Flags().StringVarP(&Recipient, "recipient", "r", "", "recipient address")
	transferBaseCurrencyCmd.Flags().StringVarP(&Amount, "amount", "a", "", "transfer amount")
	transferBaseCurrencyCmd.Flags().Uint64VarP(&Decimals, "decimals", "d", 18, "base token decimals")
	flags.MarkFlagsAsRequired(transferBaseCurrencyCmd, "recipient", "amount")
}

func init() {
	BindTransferCmdFlags()
}
func validateTransferBaseCurrencyFlags(cmd *cobra.Command, args []string) error {
	if !common.IsHexAddress(Recipient) {
		return fmt.Errorf("invalid recipient address %s", Recipient)
	}
	return nil
}

func processTransferBaseCurrencyFlags(cmd *cobra.Command, args []string) error {
	var err error
	recipientAddress = common.HexToAddress(Recipient)
	decimals := big.NewInt(int64(Decimals))
	weiAmount, err = calls.UserAmountToWei(Amount, decimals)
	return err
}
func transferBaseCurrency(cmd *cobra.Command, args []string, txFabric calls.TxFabric) error {

	// fetch global flag values
	url, gasLimit, gasPrice, senderKeyPair, err := flags.GlobalFlagValues(cmd)
	if err != nil {
		return fmt.Errorf("could not get global flags: %v", err)
	}

	ethClient, err := evmclient.NewEVMClientFromParams(url, senderKeyPair.PrivateKey(), gasPrice)
	if err != nil {
		log.Error().Err(fmt.Errorf("eth client intialization error: %v", err))
		return err
	}

	txHash, err := calls.Transact(ethClient, txFabric, &recipientAddress, nil, gasLimit, weiAmount)
	if err != nil {
		log.Error().Err(fmt.Errorf("base currency deposit error: %v", err))
		return err
	}

	log.Debug().Msgf("base currency transaction hash: %s", txHash.Hex())

	log.Info().Msgf("%s tokens were transferred to %s from %s", Amount, recipientAddress.Hex(), senderKeyPair.CommonAddress().String())
	return nil
}

func confirmTransfer(cmd *cobra.Command, args []string) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Send transaction %s(%d) to %s (Y/N)?", Amount, Decimals, Recipient)
		s, _ := reader.ReadString('\n')

		s = strings.ToLower(strings.TrimSuffix(s, "\n"))

		if strings.Compare(s, "n") == 0 {
			os.Exit(0)
		} else if strings.Compare(s, "y") == 0 {
			break
		} else {
			continue
		}
	}
}
