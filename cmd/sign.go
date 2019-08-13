package cmd

import (
	"fmt"
	"github.com/niclabs/dhsm-signer/signer"
	"github.com/spf13/cobra"
	"os"
	"time"
)

var args signer.SignArgs

func init() {
	signCmd.Flags().StringVarP(&args.Zone, "zone", "z", "", "Zone name")
	signCmd.Flags().BoolVarP(&args.CreateKeys, "create-keys", "c", false, "Creates a new pair of keys, outdating all valid keys.")
	signCmd.Flags().BoolVarP(&args.NSEC3, "nsec3", "3", false, "Use NSEC3 instead of NSEC (default: NSEC)")
	signCmd.Flags().BoolVarP(&args.OptOut, "opt-out", "x", false, "Use NSEC3 with opt-out")
	signCmd.Flags().StringP("file", "f", "", "Full path to zone file to be signed")
	signCmd.Flags().StringP("output", "o", "", "Output for the signed zone file")
	signCmd.Flags().StringP("expiration-date", "e", "", "Expiration Date, in YYYYMMDD format. Default is one more year from now.")
	signCmd.Flags().StringP("p11lib", "p", "", "Full path to PKCS11 lib file")
	signCmd.Flags().StringP("user-key", "k", "1234", "HSM User Login Key (default is 1234)")
	signCmd.Flags().StringP("key-label", "l", "dHSM-signer", "Label of HSM Signer Key")

	_ = signCmd.MarkFlagRequired("zone")
	_ = signCmd.MarkFlagRequired("file")
	_ = signCmd.MarkFlagRequired("p11lib")
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Signs a DNS Zone using the provided PKCS#11 library",
	RunE: func(cmd *cobra.Command, _ []string) error {
		filepath, _ := cmd.Flags().GetString("file")
		out, _ := cmd.Flags().GetString("output")
		p11lib, _ := cmd.Flags().GetString("p11lib")
		key, _ := cmd.Flags().GetString("user-key")
		label, _ := cmd.Flags().GetString("key-label")
		expDateStr, _ := cmd.Flags().GetString("expiration-date")

		if err := signer.FilesExist(p11lib, filepath); err != nil {
			return err
		}
		file, err := os.Open(filepath)
		if err != nil {
			return err
		}
		defer file.Close()
		args.File = file

		s, err := signer.NewSession(p11lib, key, label, Log)
		if err != nil {
			return err
		}
		defer s.End()

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

		if _, err := s.Sign(&args); err != nil {
			return err
		}
		Log.Printf("File signed successfully.")
		return nil
	},
}
