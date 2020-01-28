package cmd

import (
	"fmt"
	"github.com/niclabs/hsm-tools/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	signCmd.PersistentFlags().StringP("file", "f", "", "Full path to zone file to be signed")
	signCmd.PersistentFlags().StringP("output", "o", "", "Output for the signed zone file")
	signCmd.PersistentFlags().StringP("zone", "z", "", "Zone name")
	signCmd.PersistentFlags().BoolP("create-keys", "c", false, "Creates a new pair of keys, outdating all valid keys.")
	signCmd.PersistentFlags().StringP("sign-algorithm", "a", "rsa", "Algorithm used in signing")
	signCmd.PersistentFlags().BoolP("nsec3", "3", false, "Use NSEC3 instead of NSEC (default: NSEC)")
	signCmd.PersistentFlags().BoolP("opt-out", "x", false, "Use NSEC3 with opt-out")
	signCmd.PersistentFlags().StringP("expiration-date", "e", "", "Expiration Date, in YYYYMMDD format. Default is one more year from now.")
	signCmd.PersistentFlags().StringP("user-key", "k", "1234", "HSM User Login Key (default is 1234)")
	signCmd.PersistentFlags().StringP("key-label", "l", "HSM-tools", "Label of HSM Signer Key")

	pkcs11Cmd.PersistentFlags().StringP("p11lib", "p", "", "Full path to PKCS11 lib file")
	fileCmd.PersistentFlags().StringP("keyfile", "K", "", "Full path to key file")


	viper.BindPFlag("user-key", signCmd.PersistentFlags().Lookup("user-key"))
	viper.BindPFlag("key-label", signCmd.PersistentFlags().Lookup("key-label"))

	viper.BindPFlag("file", signCmd.PersistentFlags().Lookup("file"))
	viper.BindPFlag("output", signCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("zone", signCmd.PersistentFlags().Lookup("zone"))
	viper.BindPFlag("create-keys", signCmd.PersistentFlags().Lookup("create-keys"))
	viper.BindPFlag("sign-algorithm", signCmd.PersistentFlags().Lookup("sign-algorithm"))
	viper.BindPFlag("nsec3", signCmd.PersistentFlags().Lookup("nsec3"))
	viper.BindPFlag("opt-out", signCmd.PersistentFlags().Lookup("opt-out"))
	viper.BindPFlag("expiration-date", signCmd.PersistentFlags().Lookup("expiration-date"))

	viper.BindPFlag("p11lib", pkcs11Cmd.PersistentFlags().Lookup("p11lib"))

	viper.BindPFlag("keyfile", fileCmd.PersistentFlags().Lookup("keyfile"))


	signCmd.AddCommand(pkcs11Cmd)
	signCmd.AddCommand(fileCmd)
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Signs a DNS Zone using the provided PKCS#11 library or a file",
}

var pkcs11Cmd = &cobra.Command{
	Use:   "pkcs11",
	Short: "uses a PKCS#11 library to sign the zone",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, err := newContext()
		if err != nil {
			return err
		}
		p11lib := viper.GetString("p11lib")
		if len(p11lib) == 0 {
			return fmt.Errorf("p11lib not specified")
		}

		if err := filesExist(p11lib); err != nil {
			return err
		}

		if err := ctx.PKCS11Sign(p11lib); err != nil {
			ctx.Log.Printf("File could not be signed.")
			return err
		}
		ctx.Log.Printf("File signed successfully.")
		return nil
	},
}

var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "uses keys from a file to sign the zone",
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, err := newContext()
		if err != nil {
			return err
		}
		keyfile := viper.GetString("keyfile")
		if len(keyfile) == 0 {
			return fmt.Errorf("keyfile not specified")
		}

		if err := filesExist(keyfile); err != nil {
			return err
		}

		if err := ctx.FileSign(keyfile); err != nil {
			ctx.Log.Printf("File could not be signed.")
			return err
		}
		ctx.Log.Printf("File signed successfully.")
		return nil
	},
}


func newContext() (*signer.Context, error) {
	createKeys := viper.GetBool("create-keys")
	zone := viper.GetString("zone")
	nsec3 := viper.GetBool("nsec3")
	optOut := viper.GetBool("opt-out")

	filepath := viper.GetString("file")
	out := viper.GetString("output")
	key := viper.GetString("user-key")
	label := viper.GetString("key-label")
	expDateStr := viper.GetString("expiration-date")
	signAlgorithm := viper.GetString("sign-algorithm")

	if len(filepath) == 0 {
		return nil, fmt.Errorf("input file path not specified")
	}
	if len(zone) == 0 {
		return nil, fmt.Errorf("zone not specified")
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("output file path not specified")
	}

	if err := filesExist(filepath); err != nil {
		return nil, err
	}

	return signer.NewContext(&signer.ContextConfig{
		Zone:          zone,
		CreateKeys:    createKeys,
		NSEC3:         nsec3,
		OptOut:        optOut,
		MinTTL:        0,
		Label:         label,
		SignAlgorithm: signAlgorithm,
		Key:           key,
		ExpDateStr:    expDateStr,
		OutputPath:    filepath,
	}, Log)
}
