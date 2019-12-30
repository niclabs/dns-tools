package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"log"
	"os"
)

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is /etc/dhsm-signer/config.toml)")
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(resetKeysCmd)
	Log = log.New(os.Stderr, "", 0)
}

var Log *log.Logger

var rootCmd = &cobra.Command{
	Use:   "dhsm-signer",
	Short: "Signs a DNS zone using a PKCS11 Device",
	Long: `Allows to sign a DNS zone using a PKCS#11 device.
	
	For more information, visit "https://github.com/niclabs/dhsm-signer".`,
}

func Execute() {

	if err := rootCmd.Execute(); err != nil {
		Log.Printf("Error: %s", err)
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc/dhsm-signer/")
		viper.AddConfigPath("./")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}
