package cmd

import (
	"fmt"
	"github.com/niclabs/hsm-tools/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	resetKeysCmd.Flags().StringP("p11lib", "p", "", "Full path to PKCS11 lib file")
	resetKeysCmd.Flags().StringP("user-key", "k", "1234", "HSM User Login Key (default is 1234)")
	resetKeysCmd.Flags().StringP("key-label", "l", "HSM-tools", "Label of HSM Signer Key")
	signCmd.Flags().StringP("sign-algorithm", "a", "rsa", "Algorithm of key to reset")
	viper.BindPFlag("p11lib", resetKeysCmd.Flags().Lookup("p11lib"))
	viper.BindPFlag("user-key", resetKeysCmd.Flags().Lookup("user-key"))
	viper.BindPFlag("key-label", resetKeysCmd.Flags().Lookup("key-label"))
	viper.BindPFlag("sign-algorithm", signCmd.Flags().Lookup("sign-algorithm"))

}

var resetKeysCmd = &cobra.Command{
	Use:   "reset-pkcs11-keys",
	Short: "Deletes all the keys registered in the HSM with specified key label and algorithm",
	RunE: func(cmd *cobra.Command, args []string) error {
		p11lib, _ := cmd.Flags().GetString("p11lib")

		if len(p11lib) == 0 {
			return fmt.Errorf("p11lib not specified")
		}

		key := viper.GetString("user-key")
		label := viper.GetString("key-label")
		algorithm := viper.GetString("sign-algorithm")
		if err := filesExist(p11lib); err != nil {
			return err
		}
		ctx, err := signer.NewContext(&signer.ContextConfig{
			Label:         label,
			SignAlgorithm: algorithm,
			Key:           key,

		}, Log)
		if err != nil {
			return err
		}
		if err = ctx.PKCS11DestroyKeys(p11lib); err != nil {
			Log.Printf("Error destroying keys.")
			return err
		}
		Log.Printf("All keys destroyed.")
		return nil
	},
}
