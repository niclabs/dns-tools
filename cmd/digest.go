package cmd

import (
	"fmt"
	"github.com/niclabs/hsm-tools/hsmtools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	digestCmd.PersistentFlags().StringP("file", "f", "", "Full path to zone file")
	digestCmd.PersistentFlags().StringP("zone", "z", "", "Zone name")
	digestCmd.PersistentFlags().StringP("output", "o", "", "Full path to output file")
}

var digestCmd = &cobra.Command{
	Use:   "digest",
	Short: "Adds DigestEnabled RR to the zone",
	RunE:  digest,
}

func digest(cmd *cobra.Command, args []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	zonePath := viper.GetString("file")
	zone := viper.GetString("zone")
	out := viper.GetString("output")

	if len(zonePath) == 0 {
		return fmt.Errorf("input file zonePath not specified")
	}
	if len(zone) == 0 {
		return fmt.Errorf("zone not specified")
	}
	if err := filesExist(zonePath); err != nil {
		return err

	}

	var zoneFile io.ReadCloser
	var outFile io.WriteCloser
	var err error
	zoneFile, err = os.Open(zonePath)
	if err != nil {
		return err
	}
	defer zoneFile.Close()

	if len(out) == 0 {
		pathExt := filepath.Ext(zonePath)
		pathName := strings.TrimSuffix(filepath.Base(zonePath), pathExt)
		out = filepath.Join(filepath.Dir(zonePath), pathName+"-digested"+pathExt)
	}

	outFile, err = os.Create(out)
	if err != nil {
			return err
		}
	defer outFile.Close()

	ctx := &hsmtools.Context{
		Config: &hsmtools.ContextConfig{
			Zone: zone,
		},
		File:   zoneFile,
		Output: outFile,
		Log:    Log,
	}
	if err := ctx.Digest(); err != nil {
		return err
	}
	Log.Printf("zone digested successfully in %s.", out)
	return nil
}
