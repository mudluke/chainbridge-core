package dummy

import (
	"context"
	"math/big"

	"github.com/ChainSafe/chainbridge-core/chains/evm/calls/evmgaspricer"
)

type GasPricer interface {
	GasPrice(priority *uint8) ([]*big.Int, error)
}

type StaticGasPriceDeterminant struct {
	client evmgaspricer.GasPriceClient
	opts   *evmgaspricer.GasPricerOpts
}

func NewStaticGasPriceDeterminant(client evmgaspricer.GasPriceClient, opts *evmgaspricer.GasPricerOpts) *StaticGasPriceDeterminant {
	return &StaticGasPriceDeterminant{client: client, opts: opts}
}

func (gasPricer *StaticGasPriceDeterminant) GasPrice(priority *uint8) ([]*big.Int, error) {
	var gasPrice []*big.Int

	suggest, err := gasPricer.client.SuggestGasPrice(context.TODO())
	if err != nil {
		return nil, err
	}

	switch *priority {
	// slow
	case 0:
		gasPrice = []*big.Int{big.NewInt(0).Add(suggest, big.NewInt(50000000000))}
	// fast
	case 2:
		gasPrice = []*big.Int{big.NewInt(0).Add(suggest, big.NewInt(140000000000))}
	// medium
	default:
		gasPrice = []*big.Int{big.NewInt(0).Add(suggest, big.NewInt(80000000000))}
	}
	return gasPrice, nil
}
