package cmd

import (
	"fmt"
	"github.com/niclabs/dns-tools/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

func init() {
	verifyCmd.PersistentFlags().StringP("file", "f", "", "Full path to zone file to be verified")
	verifyCmd.PersistentFlags().StringP("zone", "z", "", "Zone name")
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verification options",
	RunE:  verify,
}

func verify(cmd *cobra.Command, args []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	path := viper.GetString("file")
	zone := viper.GetString("zone")

	if len(path) == 0 {
		return fmt.Errorf("input file path not specified")
	}

	if err := filesExist(path); err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:     zone,
			FilePath: path,
		},
		File: file,
		Log:  commandLog,
	}

	if err := ctx.VerifyFile(); err != nil {
		commandLog.Printf("Zone Signature: %s", err)
	} else {
		commandLog.Printf("Zone Signature: Verified Successfully.")
	}
	if err := ctx.VerifyDigest(); err != nil {
		commandLog.Printf("Zone Digest: %s", err)
	} else {
		commandLog.Printf("Zone Digest: Verified Successfully.")
	}
	return nil
}
