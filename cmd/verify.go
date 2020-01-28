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
	signCmd.Flags().StringP("zone", "z", "", "Zone name")
	viper.BindPFlag("file", verifyCmd.Flags().Lookup("file"))
	viper.BindPFlag("zone", signCmd.Flags().Lookup("zone"))
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a signed file.",
	RunE: func(cmd *cobra.Command, args []string) error {

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
		Log.Printf("File verified successfully.")
		return nil
	},
}
