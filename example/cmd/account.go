package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/ChainSafe/chainbridge-core/crypto"
	"github.com/ChainSafe/chainbridge-core/crypto/secp256k1"
	"github.com/ChainSafe/chainbridge-core/crypto/sr25519"
	"github.com/ChainSafe/chainbridge-core/example/app"
	"github.com/ChainSafe/chainbridge-core/keystore"
	log "github.com/ChainSafe/log15"
	"github.com/spf13/cobra"
)

// dataHandler is a struct which wraps any extra data our CMD functions need that cannot be passed through parameters
type dataHandler struct {
	datadir string
}

// wrapHandler takes in a Cmd function (all declared below) and wraps
// it in the correct signature for the Cli Commands
func wrapHandler(hdl func(cmd *cobra.Command, args []string, dh *dataHandler) error) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		err := startLogger(cmd)
		if err != nil {
			return err
		}

		datadir, err := getDataDir(cmd)
		if err != nil {
			return fmt.Errorf("failed to access the datadir: %w", err)
		}

		return hdl(cmd, args, &dataHandler{datadir: datadir})
	}
}

// getDataDir obtains the path to the keystore and returns it as a string
func getDataDir(cmd *cobra.Command) (string, error) {
	// key directory is datadir/keystore/
	keystore := ""
	cmd.Flags().StringVarP(&keystore, "keystore", "k", app.DefaultKeystorePath, "path to keystore directory")
	if dir := keystore; dir != "" {
		datadir, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		log.Trace(fmt.Sprintf("Using keystore dir: %s", datadir))
		return datadir, nil
	}
	return "", fmt.Errorf("datadir flag not supplied")
}

func startLogger(cmd *cobra.Command) error {
	logger := log.Root()
	handler := logger.GetHandler()
	var lvl log.Lvl

	verbosity := ""
	cmd.Flags().StringVarP(&verbosity, "verbosity", "v", log.LvlInfo.String(), "Supports levels crit (silent) to trce (trace)")

	if lvlToInt, err := strconv.Atoi(verbosity); err == nil {
		lvl = log.Lvl(lvlToInt)
	} else if lvl, err = log.LvlFromString(verbosity); err != nil {
		return err
	}
	log.Root().SetHandler(log.LvlFilterHandler(lvl, handler))

	return nil
}

// handleImportCmd imports external keystores into the bridge
func handleImportCmd(cmd *cobra.Command, args []string, dh *dataHandler) error {
	log.Info("Importing key...")

	if privkeyflag, err := cmd.Flags().GetBool("privateKey"); err == nil && privkeyflag {
		var password []byte = nil

		privateKey := keystore.GetPassword("Enter the hexadecimal private key for encryption:")
		_, err = importPrivKey(cmd, crypto.Secp256k1Type, dh.datadir, string(privateKey), password)
		if err != nil {
			return fmt.Errorf("failed to import private key: %w", err)
		}
	} else if len(args) > 0 {
		if keyimport := args[0]; keyimport != "" {
			_, err = importKey(keyimport, dh.datadir)
			if err != nil {
				return fmt.Errorf("failed to import key: %w", err)
			}
		}
	} else {
		return fmt.Errorf("Must provide a key to import.")
	}

	return nil
}

// keystoreDir returnns the absolute filepath of the keystore directory given a datadir
// by default, it is ./keys/
// otherwise, it is datadir/keys/
func keystoreDir(keyPath string) (keystorepath string, err error) {
	// datadir specified, return datadir/keys as absolute path
	if keyPath != "" {
		keystorepath, err = filepath.Abs(keyPath)
		if err != nil {
			return "", err
		}
	} else {
		// datadir not specified, use default
		keyPath = app.DefaultKeystorePath

		keystorepath, err = filepath.Abs(keyPath)
		if err != nil {
			return "", fmt.Errorf("could not create keystore file path: %w", err)
		}
	}

	// if datadir does not exist, create it
	if _, err = os.Stat(keyPath); os.IsNotExist(err) {
		err = os.Mkdir(keyPath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}

	// if datadir/keystore does not exist, create it
	if _, err = os.Stat(keystorepath); os.IsNotExist(err) {
		err = os.Mkdir(keystorepath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}

	return keystorepath, nil
}

// importPrivKey imports a private key into a keypair
func importPrivKey(cmd *cobra.Command, keytype, datadir, key string, password []byte) (string, error) {
	if password == nil {
		password = keystore.GetPassword("Enter password to encrypt keystore file:")
	}
	keystorepath, err := keystoreDir(datadir)

	if keytype == "" {
		log.Info("Using default key type", "type", keytype)
		keytype = crypto.Secp256k1Type
	}

	var kp crypto.Keypair

	if keytype == crypto.Sr25519Type {
		// generate sr25519 keys
		network, _ := cmd.Flags().GetString("network")
		kp, err = sr25519.NewKeypairFromSeed(key, network)
		if err != nil {
			return "", fmt.Errorf("could not generate sr25519 keypair from given string: %w", err)
		}
	} else if keytype == crypto.Secp256k1Type {
		// Hex must not have leading 0x
		if key[0:2] == "0x" {
			kp, err = secp256k1.NewKeypairFromString(key[2:])
		} else {
			kp, err = secp256k1.NewKeypairFromString(key)
		}

		if err != nil {
			return "", fmt.Errorf("could not generate secp256k1 keypair from given string: %w", err)
		}
	} else {
		return "", fmt.Errorf("invalid key type: %s", keytype)
	}

	fp, err := filepath.Abs(keystorepath + "/" + kp.Address() + ".key")
	if err != nil {
		return "", fmt.Errorf("invalid filepath: %w", err)
	}

	file, err := os.OpenFile(filepath.Clean(fp), os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", fmt.Errorf("Unable to Open File: %w", err)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Error("import private key: could not close keystore file")
		}
	}()

	err = keystore.EncryptAndWriteToFile(file, kp, password)
	if err != nil {
		return "", fmt.Errorf("could not write key to file: %w", err)
	}

	log.Info("private key imported", "address", kp.Address(), "file", fp)
	return fp, nil

}

// importKey imports a key specified by its filename to datadir/keystore/
// it saves it under the filename "[publickey].key"
// it returns the absolute path of the imported key file
func importKey(filename, datadir string) (string, error) {
	keystorepath, err := keystoreDir(datadir)
	if err != nil {
		return "", fmt.Errorf("could not get keystore directory: %w", err)
	}

	importdata, err := ioutil.ReadFile(filepath.Clean(filename))
	if err != nil {
		return "", fmt.Errorf("could not read import file: %w", err)
	}

	ksjson := new(keystore.EncryptedKeystore)
	err = json.Unmarshal(importdata, ksjson)
	if err != nil {
		return "", fmt.Errorf("could not read file contents: %w", err)
	}

	keystorefile, err := filepath.Abs(keystorepath + "/" + ksjson.Address[2:] + ".key")
	if err != nil {
		return "", fmt.Errorf("could not create keystore file path: %w", err)
	}

	err = ioutil.WriteFile(keystorefile, importdata, 0600)
	if err != nil {
		return "", fmt.Errorf("could not write to keystore directory: %w", err)
	}

	log.Info("successfully imported key", "address", ksjson.Address, "file", keystorefile)
	return keystorefile, nil
}
