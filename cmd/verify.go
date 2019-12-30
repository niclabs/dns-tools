package cmd

import (
	"fmt"
	"github.com/niclabs/dhsm-signer/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

func init() {
	verifyCmd.Flags().StringP("file", "f", "", "Full path to zone file to be verified")
	viper.BindPFlag("file", verifyCmd.Flags().Lookup("file"))
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a signed file.",
	RunE: func(cmd *cobra.Command, args []string) error {

		filepath :=  viper.GetString("file")

		if len(filepath) == 0 {
			return fmt.Errorf("input file path not specified")
		}


		if err := signer.FilesExist(filepath); err != nil {
			return err
		}

		file, err := os.Open(filepath)
		if err != nil {
			return err
		}

		if err := signer.VerifyFile(file, Log); err != nil {
			return err
		}
		Log.Printf("File verified successfully.")
		return nil
	},
}
