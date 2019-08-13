package cmd

import (
	"github.com/niclabs/dhsm-signer/signer"
	"github.com/spf13/cobra"
	"os"
)

func init() {
	verifyCmd.Flags().StringP("file", "f", "", "Full path to zone file to be verified")
	_ = verifyCmd.MarkFlagRequired("file")
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a signed file.",
	RunE: func(cmd *cobra.Command, args []string) error {

		filepath, _ := cmd.Flags().GetString("file")

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
