package cmd

import (
	"fmt"
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
		file, _ := cmd.Flags().GetString("file")
		_, err := os.Stat(file)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("File %s doesn't exist\n", file)
			} else {
				return fmt.Errorf("Error reading %s: %s \n", file, err)
			}
		}
		if err := signer.VerifyFile(file); err != nil {
			return err
		}
		Log.Printf("File verified successfully.")
		return nil
	},
}
