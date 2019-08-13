package cmd

import (
	"github.com/niclabs/dhsm-signer/signer"
	"github.com/spf13/cobra"
)

func init() {
	resetKeysCmd.Flags().StringP("p11lib", "p", "", "Full path to PKCS11 lib file")
	resetKeysCmd.Flags().StringP("user-key", "k", "1234", "HSM User Login Key (default is 1234)")
	resetKeysCmd.Flags().StringP("key-label", "l", "dHSM-signer", "Label of HSM Signer Key")
	_ = resetKeysCmd.MarkFlagRequired("p11lib")
}

var resetKeysCmd = &cobra.Command{
	Use:   "reset-keys",
	Short: "Deletes all the keys registered in the HSM with specified key label",
	RunE: func(cmd *cobra.Command, args []string) error {
		p11lib, _ := cmd.Flags().GetString("p11lib")
		key, _ := cmd.Flags().GetString("user-key")
		label, _ := cmd.Flags().GetString("key-label")
		if err := FilesExist(p11lib); err != nil {
			return err
		}
		s, err := signer.NewSession(p11lib, key, label)
		if err != nil {
			return err
		}
		defer s.End()
		if err := s.DestroyAllKeys(); err != nil {
			return err
		}
		Log.Printf("All keys destroyed.")
		return nil
	},
}
