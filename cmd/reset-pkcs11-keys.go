package cmd

import (
	"fmt"
	"github.com/niclabs/dns-tools/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	resetPKCS11KeysCmd.Flags().StringP("p11lib", "p", "", "Full path to PKCS11Type lib file")
	resetPKCS11KeysCmd.Flags().StringP("user-key", "k", "1234", "HSM User Login PKCS11Key")
	resetPKCS11KeysCmd.Flags().StringP("key-label", "l", "HSM-tools", "Label of HSM Signer PKCS11Key")
}

var resetPKCS11KeysCmd = &cobra.Command{
	Use:   "reset-pkcs11-keys",
	Short: "Deletes all the keys registered in the HSM with specified key label and algorithm",
	RunE:  resetPKCS11Keys,
}

func resetPKCS11Keys(cmd *cobra.Command, args []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	p11lib := viper.GetString("p11lib")
	if len(p11lib) == 0 {
		return fmt.Errorf("p11lib not specified")
	}

	key := viper.GetString("user-key")
	label := viper.GetString("key-label")
	if err := filesExist(p11lib); err != nil {
		return err
	}
	ctx, err := tools.NewContext(&tools.ContextConfig{}, commandLog)
	if err != nil {
		return err
	}
	defer ctx.Close()
	session, err := ctx.NewPKCS11Session(key, label, p11lib)
	if err != nil {
		return err
	}
	defer session.End()
	if err := session.DestroyAllKeys(); err != nil {
		return err
	}
	commandLog.Printf("All keys destroyed.")
	return nil
}
