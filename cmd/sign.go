package cmd

import (
	"fmt"
	"github.com/niclabs/hsm-tools/signer"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"time"
)

var args signer.SignArgs

func init() {
	signCmd.Flags().StringP("file", "f", "", "Full path to zone file to be signed")
	signCmd.Flags().StringP("output", "o", "", "Output for the signed zone file")
	signCmd.Flags().StringP("zone", "z", "", "Zone name")
	signCmd.Flags().BoolP("create-keys", "c", false, "Creates a new pair of keys, outdating all valid keys.")
	signCmd.Flags().BoolP("nsec3", "3", false, "Use NSEC3 instead of NSEC (default: NSEC)")
	signCmd.Flags().BoolP("opt-out", "x", false, "Use NSEC3 with opt-out")
	signCmd.Flags().StringP("expiration-date", "e", "", "Expiration Date, in YYYYMMDD format. Default is one more year from now.")
	signCmd.Flags().StringP("p11lib", "p", "", "Full path to PKCS11 lib file")
	signCmd.Flags().StringP("user-key", "k", "1234", "HSM User Login Key (default is 1234)")
	signCmd.Flags().StringP("key-label", "l", "HSM-tools", "Label of HSM Signer Key")

	viper.BindPFlag("p11lib", signCmd.Flags().Lookup("p11lib"))
	viper.BindPFlag("user-key", signCmd.Flags().Lookup("user-key"))
	viper.BindPFlag("key-label", signCmd.Flags().Lookup("key-label"))

	viper.BindPFlag("file", signCmd.Flags().Lookup("file"))
	viper.BindPFlag("output", signCmd.Flags().Lookup("output"))
	viper.BindPFlag("zone", signCmd.Flags().Lookup("zone"))
	viper.BindPFlag("create-keys", signCmd.Flags().Lookup("create-keys"))
	viper.BindPFlag("nsec3", signCmd.Flags().Lookup("nsec3"))
	viper.BindPFlag("opt-out", signCmd.Flags().Lookup("opt-out"))
	viper.BindPFlag("expiration-date", signCmd.Flags().Lookup("expiration-date"))
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Signs a DNS Zone using the provided PKCS#11 library",
	RunE: func(cmd *cobra.Command, _ []string) error {

		zone := viper.GetString("zone")
		createKeys := viper.GetBool("create-keys")
		nsec3 := viper.GetBool("nsec3")
		optOut := viper.GetBool("opt-out")


		filepath := viper.GetString("file")
		out := viper.GetString("output")
		p11lib := viper.GetString("p11lib")
		key := viper.GetString("user-key")
		label := viper.GetString("key-label")
		expDateStr := viper.GetString("expiration-date")

		if len(filepath) == 0 {
			return fmt.Errorf("input file path not specified")
		}
		if len(zone) == 0 {
			return fmt.Errorf("zone not specified")
		}
		if len(out) == 0 {
			return fmt.Errorf("output file path not specified")
		}
		if len(p11lib) == 0 {
			return fmt.Errorf("p11lib not specified")
		}

		args.Zone = zone
		args.CreateKeys = createKeys
		args.NSEC3 = nsec3
		args.OptOut = optOut

		if err := signer.FilesExist(p11lib, filepath); err != nil {
			return err
		}
		file, err := os.Open(filepath)
		if err != nil {
			return err
		}
		defer file.Close()
		args.File = file

		if len(expDateStr) > 0 {
			parsedDate, err := time.Parse("20160102", expDateStr)
			if err != nil {
				return fmt.Errorf("cannot parse expiration date: %s", err)
			}
			args.SignExpDate = parsedDate
		}

		if len(out) > 0 {
			writer, err := os.Create(out)
			if err != nil {
				return fmt.Errorf("couldn't create out file in path %s: %s", out, err)
			}
			defer writer.Close()
			args.Output = writer
		} else {
			args.Output = os.Stdout
		}

		/* SIGNATURE: PKCS11 CASE */
		s, err := signer.NewSession(p11lib, key, label, Log)
		if err != nil {
			return err
		}
		defer s.End()
		if _, err := s.Sign(&args); err != nil {
			return err
		}
		Log.Printf("File signed successfully.")
		return nil
	},
}
