
.PHONY: help run build install license
all: help

## license: Adds license header to missing files.
license:
	@echo "  >  \033[32mAdding license headers...\033[0m "
	GO111MODULE=off go get -u github.com/google/addlicense
	addlicense -c "ChainSafe Systems" -f ./scripts/header.txt -y 2021 .

## license-check: Checks for missing license headers
license-check:
	@echo "  >  \033[Checking for license headers...\033[0m "
	GO111MODULE=off go get -u github.com/google/addlicense
	addlicense -check -c "ChainSafe Systems" -f ./scripts/header.txt -y 2021 .


coverage:
	go tool cover -func cover.out | grep total | awk '{print $3}'

test:
	./scripts/test.sh

## Install dependency subkey
install-subkey:
	curl https://getsubstrate.io -sSf | bash -s -- --fast
	cargo install --force --git https://github.com/paritytech/substrate subkey

genmocks:
	mockgen -destination=./chains/evm/evmgaspricer/mock/gas-pricer.go -source=./chains/evm/evmgaspricer/gas-pricer.go
	mockgen -destination=./relayer/mock/relayer.go -source=./relayer/relayer.go
	mockgen -source=chains/evm/calls/utils.go -destination=chains/evm/calls/mock/utils.go

e2e-setup:
	docker-compose --file=./e2e/evm-evm/docker-compose.e2e.yml up

e2e-test:
	./scripts/int_tests.sh

local-setup:
	./scripts/local_setup.sh
