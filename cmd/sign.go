package cmd

import (
	"fmt"
	"github.com/niclabs/hsm-tools/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

func init() {
	signCmd.PersistentFlags().StringP("file", "f", "", "Full path to zone file to be signed")
	signCmd.PersistentFlags().StringP("zone", "z", "", "Zone name")
	signCmd.PersistentFlags().StringP("output", "o", "", "Output for the signed zone file")
	signCmd.PersistentFlags().BoolP("create-keys", "c", false, "Creates a new pair of keys, outdating all valid keys.")
	signCmd.PersistentFlags().StringP("sign-algorithm", "a", "rsa", "Algorithm used in signing")
	signCmd.PersistentFlags().BoolP("nsec3", "3", false, "Use NSEC3 instead of NSEC (default: NSEC)")
	signCmd.PersistentFlags().BoolP("opt-out", "x", false, "Use NSEC3 with opt-out")
	signCmd.PersistentFlags().StringP("expiration-date", "e", "", "Expiration Date, in YYYYMMDD format. Default is one more year from now.")

	pkcs11Cmd.PersistentFlags().StringP("user-key", "k", "1234", "HSM User Login PKCS11Key (default is 1234)")
	pkcs11Cmd.PersistentFlags().StringP("key-label", "l", "HSM-tools", "Label of HSM Signer PKCS11Key")
	pkcs11Cmd.PersistentFlags().StringP("p11lib", "p", "", "Full path to PKCS11Type lib file")
	signCmd.AddCommand(pkcs11Cmd)

	fileCmd.PersistentFlags().StringP("zsk-keyfile", "Z", "", "Full path to ZSK key file")
	fileCmd.PersistentFlags().StringP("ksk-keyfile", "K", "", "Full path to KSK key file")
	signCmd.AddCommand(fileCmd)
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Signs a DNS Zone using the provided PKCS#11 library or a file",
}

var pkcs11Cmd = &cobra.Command{
	Use:   "pkcs11",
	Short: "uses a PKCS#11 library to sign the zone",
	RunE:  runPKCS11,
}

var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "uses keys from a file to sign the zone",
	RunE:  runFile,
}

func runPKCS11(cmd *cobra.Command, _ []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	conf, err := newContextConfig()
	if err != nil {
		return err
	}
	ctx, err := signer.NewContext(conf, Log)
	if err != nil {
		return err
	}
	defer ctx.Close()
	p11lib := viper.GetString("p11lib")
	if len(p11lib) == 0 {
		return fmt.Errorf("p11lib not specified")
	}
	key := viper.GetString("key")
	if len(key) == 0 {
		return fmt.Errorf("key not specified")
	}
	label := viper.GetString("label")
	if len(label) == 0 {
		return fmt.Errorf("label not specified")
	}
	if err := filesExist(p11lib); err != nil {
		return err
	}
	session, err := ctx.NewPKCS11Session(key, label, p11lib)
	if err != nil {
		return err
	}
	defer session.End()
	if _, err := signer.Sign(session); err != nil {
		ctx.Log.Printf("file could not be signed.")
		return err
	}
	ctx.Log.Printf("file signed successfully.")
	return nil
}

func runFile(cmd *cobra.Command, _ []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	conf, err := newContextConfig()
	if err != nil {
		return err
	}
	ctx, err := signer.NewContext(conf, Log)
	defer ctx.Close()
	if err != nil {
		return err
	}
	zskKeypath := viper.GetString("ksk-keyfile")
	if len(zskKeypath) == 0 {
		return fmt.Errorf("ZSK keyfile not specified")
	}
	kskKeypath := viper.GetString("zsk-keyfile")
	if len(kskKeypath) == 0 {
		return fmt.Errorf("KSK keyfile not specified")
	}

	fileFlags := os.O_RDWR|os.O_CREATE
	if ctx.CreateKeys {
		fileFlags |= os.O_TRUNC // Truncate old file
	}

	zskFile, err := os.OpenFile(zskKeypath, fileFlags, 0600)
	if err != nil {
		return err
	}
	kskFile, err := os.OpenFile(kskKeypath, fileFlags, 0600)
	if err != nil {
		return err
	}
	session, err := ctx.NewFileSession(kskFile, zskFile)
	if err != nil {
		return err
	}
	defer session.End()
	if _, err := signer.Sign(session); err != nil {
		return err
	}
	ctx.Log.Printf("sessionType signed successfully.")
	return nil
}

func newContextConfig() (*signer.ContextConfig, error) {
	createKeys := viper.GetBool("create-keys")
	zone := viper.GetString("zone")
	nsec3 := viper.GetBool("nsec3")
	optOut := viper.GetBool("opt-out")

	filepath := viper.GetString("file")
	out := viper.GetString("output")
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

	return &signer.ContextConfig{
		Zone:          zone,
		CreateKeys:    createKeys,
		NSEC3:         nsec3,
		OptOut:        optOut,
		MinTTL:        0,
		SignAlgorithm: signAlgorithm,
		ExpDateStr:    expDateStr,
		FilePath:      filepath,
		OutputPath:    out,
	}, nil
}
