package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "C", "", "configuration file (defaults are \"/etc/dns-tools/dns-tools-config.json\" and \"./dns-tools-config.json\")")
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(digestCmd)
	rootCmd.AddCommand(resetPKCS11KeysCmd)
	commandLog = log.New(os.Stderr, "[dns-tools] ", log.Ldate|log.Ltime)
}

var commandLog *log.Logger

var rootCmd = &cobra.Command{
	Use:   "dns-tools",
	Short: "Signs a DNS zone using a PKCS11 Device",
	Long: `Allows to sign a DNS zone using a PKCS#11 device.
	
	For more information, visit "https://github.com/niclabs/dns-tools".`,
}

// Execute executes the command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath("/etc/dns-tools/")
		viper.AddConfigPath("./")
		viper.SetConfigName("dns-tools-config")
	}

	viper.AutomaticEnv()
	if err := viper.ReadInConfig(); err == nil {
		commandLog.Println("Using config file:", viper.ConfigFileUsed())
	} else {
		commandLog.Printf("Error reading Config File: %s. Using flags only", err)
	}
}

// filesExist returns an error if any of the paths received as args does not point to a readable file.
func filesExist(filepaths ...string) error {
	for _, path := range filepaths {
		_, err := os.Stat(path)
		if err != nil || os.IsNotExist(err) {
			return fmt.Errorf("file %s doesn't exist or it has not reading permissions", path)
		}
	}
	return nil
}
