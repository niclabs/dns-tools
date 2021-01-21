package cmd

import (
	"io"
	"os"
	"github.com/niclabs/dns-tools/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	verifyCmd.PersistentFlags().StringP("file", "f", "", "Full path to zone file to be verified")
	verifyCmd.PersistentFlags().StringP("zone", "z", "", "Zone name")

	verifyCmd.PersistentFlags().StringP("verify-threshold-duration", "t", "", "Number of days it needs to be before a signature expiration to be considered as valid by the verifier. Default is empty")
	verifyCmd.PersistentFlags().StringP("verify-threshold-date", "T", "", "Exact date it needs to be before a signature expiration to be considered as expired by the verifier. It is ignored if --verify-threshold-duration is set. Default is tomorrow")
	verifyCmd.PersistentFlags().IntP("hash-digest", "d", 1, "Hash algorithm for Digest Verification: 1=sha384, 2=sha256")

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
	hashdigest := uint8(viper.GetInt("hash-digest"))

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
		HashDigest: hashdigest,
	}

	if err := ctx.VerifyFile(); err != nil {
		commandLog.Printf("Zone Signature: %s", err)
	} else {
		commandLog.Printf("Zone Signature: Verified Successfully.")
	}
	if err := ctx.VerifyDigest(); err != nil {
		commandLog.Printf("Zone Digest: %s", err)
	} else {
		commandLog.Printf("Zone Digest: Verified Successfully.")
	}
	return nil
}
