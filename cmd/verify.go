package cmd

import (
	"fmt"
	"github.com/niclabs/hsm-tools/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

func init() {
	verifyCmd.Flags().StringP("file", "f", "", "Full path to zone file to be verified")
	verifyCmd.Flags().StringP("zone", "z", "", "Zone name")
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a signed file.",
	RunE: verify,
}

func verify(cmd *cobra.Command, args []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	filepath := viper.GetString("file")
	zone := viper.GetString("zone")

	if len(filepath) == 0 {
		return fmt.Errorf("input file path not specified")
	}
	if len(zone) == 0 {
		return fmt.Errorf("zone not specified")
	}

	if err := filesExist(filepath); err != nil {
		return err
	}

	file, err := os.Open(filepath)
	if err != nil {
		return err
	}

	if err := signer.VerifyFile(zone, file, Log); err != nil {
		return err
	}
	Log.Printf("sessionType verified successfully.")
	return nil
}
