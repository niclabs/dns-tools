package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/niclabs/dns-tools/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	verifyCmd.PersistentFlags().StringP("file", "f", "", "Full path to zone file to be verified")
	verifyCmd.PersistentFlags().StringP("zone", "z", "", "Zone name")
	verifyCmd.PersistentFlags().BoolP("skip-signatures", "S", false, "Skip verification of DNSSEC signatures")
	verifyCmd.PersistentFlags().BoolP("skip-digests", "D", false, "Skip verification of ZONEMD digests")
	verifyCmd.PersistentFlags().StringP("verify-threshold-duration", "t", "", "Number of days it needs to be before a signature expiration to be considered as valid by the verifier. Default is empty")
	verifyCmd.PersistentFlags().StringP("verify-threshold-date", "T", "", "Exact date it needs to be before a signature expiration to be considered as expired by the verifier. It is ignored if --verify-threshold-duration is set. Default is tomorrow")
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verification options",
	RunE:  verify,
}

func verify(cmd *cobra.Command, args []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	path := viper.GetString("file")
	zone := viper.GetString("zone")
	skipSignatures := viper.GetBool("skip-signatures")
	skipDigests := viper.GetBool("skip-digests")

	if skipSignatures && skipDigests {
		return fmt.Errorf("at least one of the following flags should not be set: [skip-signatures, skip-digests]")
	}

	verifyThreshold, err := getExpDate(viper.GetString("verify-threshold-duration"), viper.GetString("verify-threshold-date"), DefaultVerifyThreshold)
	if err != nil {
		return err
	}
	var file io.Reader
	if len(path) == 0 {
		file = os.Stdin
	} else {
		if err := filesExist(path); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		file = f
	}

	ctx := &tools.Context{
		Config: &tools.ContextConfig{
			Zone:            zone,
			FilePath:        path,
			VerifyThreshold: verifyThreshold,
		},
		File: file,
		Log:  commandLog,
	}

	var signErr error

	if !skipSignatures {
		signErr := ctx.VerifyFile()
		if signErr != nil {
			if signErr == tools.ErrNotEnoughDNSkeys {
				commandLog.Printf("Zone Signature: There are no signatures to check")
			} else {
				commandLog.Printf("Zone Signature: Error verifying signatures: %s", signErr)
			}
		} else {
			commandLog.Printf("Zone Signature: Verified Successfully.")
		}
	} else {
		commandLog.Printf("Zone Signature: Skipped verification (verify-signatures flag is false)")
	}

	if !skipDigests {
		if digestErr := ctx.VerifyDigest(); digestErr != nil {
			commandLog.Printf("Zone Digest: %s", digestErr)
			return digestErr
		} else if signErr != nil && signErr != tools.ErrNotEnoughDNSkeys {
			commandLog.Printf("Zone Digest: Digest matches, but zone signatures verification failed.")
			return signErr
		} else {
			commandLog.Printf("Zone Digest: Verified Successfully.")
		}
	} else {
		commandLog.Printf("Zone Digest: Skipped verification (verify-digests flag is false)")
	}
	return nil
}
