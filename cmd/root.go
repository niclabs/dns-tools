package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
	"os"
)

func init() {
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(resetKeysCmd)
	Log = log.New(os.Stderr, "", 0)
}

var Log *log.Logger

var rootCmd = &cobra.Command{
	Use:   "dns-zone-signer",
	Short: "Signs a DNS zone using a PKCS11 Device",
	Long: `Allows to sign a DNS zone using a PKCS#11 device.
	
	For more information, visit "https://github.com/niclabs/dhsm-signer".`,
}

func FilesExist(files ...string) error {
	for _, file := range files {
		_, err := os.Stat(file)
		if err != nil || os.IsNotExist(err) {
			return fmt.Errorf("File %s doesn't exist or it has not reading permissions\n", file)
		}
	}
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		Log.Printf("Error: %s", err)
		os.Exit(1)
	}
}
