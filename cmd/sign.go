package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/niclabs/dns-tools/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Defaults for RRSIG signature expirations
var (
	DefaultRRSigExpiration time.Time = time.Now().AddDate(0, 3, 0)
	DefaultVerifyThreshold time.Time = time.Now()
)

func init() {
	signCmd.PersistentFlags().StringP("file", "f", "", "Full path to zone file to be signed.")
	signCmd.PersistentFlags().StringP("zone", "z", "", "Origin zone name. If it is not specified, $ORIGIN inside the file will be used as this value.")
	signCmd.PersistentFlags().StringP("output", "o", "", "Output for the signed zone file. By default is based on zone file name, with \"-signed\" at the end of the name and before the extension")
	signCmd.PersistentFlags().BoolP("create-keys", "c", false, "Creates a new pair of keys, deleting all previously valid keys.")
	signCmd.PersistentFlags().StringP("sign-algorithm", "a", "rsa", "Algorithm used in signing.")
	signCmd.PersistentFlags().BoolP("nsec3", "3", false, "Use NSEC3 instead of NSEC.")
	signCmd.PersistentFlags().BoolP("opt-out", "x", false, "Use NSEC3 with opt-out.")
	signCmd.PersistentFlags().BoolP("digest", "d", false, "If it is true, DigestEnabled RR is added to the signed zone")
	signCmd.PersistentFlags().IntP("hash-digest", "Q", 1, "Hash algorithm for Digest Verification: 1=sha384, 2=sha512")
	signCmd.PersistentFlags().BoolP("info", "i", false, "If it is true, an TXT RR is added with information about the signing process (tool and mode)")
	signCmd.PersistentFlags().BoolP("lazy", "L", false, "If it is true, the zone will be signed only if it is needed (i.e. it is not signed already, it is signed with different key, the signatures are about to expire or the original zone is newer than the signed zone)")

	signCmd.PersistentFlags().StringP("rrsig-expiration-date", "E", "", "RRSIG expiration Date, in YYYYMMDD format. It is ignored if --ksk-duration is set. Default is three months from now.")
	signCmd.PersistentFlags().StringP("rrsig-duration", "D", "", "Relative RRSIG expiration Date, in human readable format (combining numbers with labels like year(s), month(s), day(s), hour(s), minute(s), second(s)). Overrides --rrsig-date-expiration. Default is empty.")

	signCmd.PersistentFlags().StringP("verify-threshold-duration", "t", "", "Number of days it needs to be before a signature expiration to be considered as valid by the verifier. Default is empty")
	signCmd.PersistentFlags().StringP("verify-threshold-date", "T", "", "Exact date it needs to be before a signature expiration to be considered as expired by the verifier. It is ignored if --verify-threshold-duration is set. Default is tomorrow")

	signCmd.PersistentFlags().Uint16("nsec3-iterations", 0, "If --nsec3 is activated, define the number of iterations of NSEC3 hashing")
	signCmd.PersistentFlags().Uint16("nsec3-salt-length", 64, "If --nsec3 is activated and there is no --nsec3-salt-value, define the salt length in bytes.")
	signCmd.PersistentFlags().String("nsec3-salt-value", "", "If --nsec3 is activated, define the salt value in hexadecimal. Its length overrides --nsec3-salt-length")

	pkcs11Cmd.PersistentFlags().StringP("user-key", "k", "1234", "HSM User Login PKCS11Key.")
	pkcs11Cmd.PersistentFlags().StringP("key-label", "l", "HSM-tools", "Label of HSM Signer PKCS11Key.")
	pkcs11Cmd.PersistentFlags().StringP("p11lib", "p", "", "Full path to PKCS11 lib file.")
	signCmd.AddCommand(pkcs11Cmd)

	fileCmd.PersistentFlags().StringP("zsk-keyfile", "Z", "zsk.pem", "Full path to ZSK key file.")
	fileCmd.PersistentFlags().StringP("ksk-keyfile", "K", "ksk.pem", "Full path to KSK key file.")
	signCmd.AddCommand(fileCmd)
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Signs a DNS Zone using a PKCS#11 library or a file",
}

var pkcs11Cmd = &cobra.Command{
	Use:   "pkcs11",
	Short: "uses a PKCS#11 library to sign the zone",
	RunE:  signPKCS11,
}

var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "uses keys from a file to sign the zone",
	RunE:  signFile,
}

func signPKCS11(cmd *cobra.Command, _ []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	conf, err := newSignConfig()
	if err != nil {
		return err
	}
	if conf.Lazy && !needsToBeSigned(conf) {
		return fmt.Errorf("file does not need to be signed")
	}
	p11lib := viper.GetString("p11lib")
	if len(p11lib) == 0 {
		return fmt.Errorf("p11lib not specified")
	}
	key := viper.GetString("user-key")
	if len(key) == 0 {
		return fmt.Errorf("user-key not specified")
	}
	label := viper.GetString("key-label")
	if len(label) == 0 {
		return fmt.Errorf("key-label not specified")
	}
	if err := filesExist(p11lib); err != nil {
		return err
	}
	ctx, err := tools.NewContext(conf, commandLog)
	if err != nil {
		return err
	}
	defer ctx.Close()
	session, err := ctx.NewPKCS11Session(key, label, p11lib)
	if err != nil {
		return err
	}
	defer session.End()
	if _, err := tools.Sign(session); err != nil {
		ctx.Log.Printf("zone could not be signed.")
		return err
	}
	ctx.Log.Printf("zone signed successfully.")
	return nil
}

func signFile(cmd *cobra.Command, _ []string) error {
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}
	conf, err := newSignConfig()
	if err != nil {
		return err
	}
	if conf.Lazy && !needsToBeSigned(conf) {
		return fmt.Errorf("file does not need to be signed")
	}
	ctx, err := tools.NewContext(conf, commandLog)
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

	fileFlags := os.O_RDWR | os.O_CREATE
	if ctx.Config.CreateKeys {
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
	if _, err := tools.Sign(session); err != nil {
		return err
	}
	ctx.Log.Printf("zone signed successfully.")
	return nil
}

func newSignConfig() (*tools.ContextConfig, error) {
	createKeys := viper.GetBool("create-keys")
	zone := strings.ToLower(viper.GetString("zone"))
	nsec3 := viper.GetBool("nsec3")
	optOut := viper.GetBool("opt-out")
	digest := viper.GetBool("digest")
	info := viper.GetBool("info")
	lazy := viper.GetBool("lazy")

	path := viper.GetString("file")
	out := viper.GetString("output")
	hashDigest := uint8(viper.GetInt("hash-digest"))

	nsec3Iterations := uint16(viper.GetInt("nsec3-iterations"))
	nsec3SaltLength := uint8(viper.GetInt("nsec3-salt-length"))
	nsec3SaltValue := viper.GetString("nsec3-salt-value")

	if hashDigest == 0 {
		return nil, fmt.Errorf("hash-digest not specified")
	}

	signAlgorithm := viper.GetString("sign-algorithm")

	if len(path) == 0 {
		return nil, fmt.Errorf("zone file not specified")
	}
	if len(zone) == 0 {
		return nil, fmt.Errorf("zone not specified")
	}
	if len(out) == 0 {
		pathExt := filepath.Ext(path)
		pathName := strings.TrimSuffix(filepath.Base(path), pathExt)
		out = filepath.Join(filepath.Dir(path), pathName+"-signed"+pathExt)
	}

	if err := filesExist(path); err != nil {
		return nil, err
	}
	rrsigExpDate, err := getExpDate(viper.GetString("rrsig-duration"), viper.GetString("rrsig-expiration-date"), DefaultRRSigExpiration)
	if err != nil {
		return nil, err
	}

	verifyThreshold, err := getExpDate(viper.GetString("verify-threshold-duration"), viper.GetString("verify-threshold-date"), DefaultVerifyThreshold)
	if err != nil {
		return nil, err
	}

	return &tools.ContextConfig{
		Zone:            zone,
		CreateKeys:      createKeys,
		NSEC3:           nsec3,
		DigestEnabled:   digest,
		OptOut:          optOut,
		SignAlgorithm:   signAlgorithm,
		RRSIGExpDate:    rrsigExpDate,
		FilePath:        path,
		OutputPath:      out,
		Info:            info,
		Lazy:            lazy,
		VerifyThreshold: verifyThreshold,
		HashAlg:         hashDigest,
		NSEC3Iterations: nsec3Iterations,
		NSEC3SaltLength: nsec3SaltLength,
		NSEC3SaltValue:  nsec3SaltValue,
	}, nil
}

func getExpDate(durString, expDate string, def time.Time) (time.Time, error) {
	if len(durString) > 0 {
		return tools.DurationToTime(time.Now(), durString)
	}
	if len(expDate) > 0 {
		return time.Parse("20060102", expDate)
	}
	return def, nil
}

func needsToBeSigned(conf *tools.ContextConfig) bool {
	signedIsValid := false
	signedExists := false
	commandLog.Printf("Checking if file needs to be signed (--lazy flag enabled)...")
	var zoneModDate, signedModDate time.Time
	if outputStat, err := os.Stat(conf.OutputPath); err == nil {
		outputFile, err := os.Open(conf.OutputPath)
		if err != nil {
			commandLog.Printf("Error opening output file when verifying if it needs to be signed: %s", err)
			signedExists = false
		}
		defer outputFile.Close()
		zoneStat, err := os.Stat(conf.FilePath)
		if err != nil {
			commandLog.Printf("Error opening zone file when verifying if it needs to be signed: %s", err)
			return true
		}
		zoneModDate = zoneStat.ModTime()
		signedModDate = outputStat.ModTime()
		commandLog.Printf("Input Zone modification date: %s", zoneModDate)
		commandLog.Printf("Signed Zone modification date: %s", signedModDate)

		signedExists = true
		ctx := &tools.Context{
			Config: &tools.ContextConfig{
				Zone:            conf.Zone,
				FilePath:        conf.OutputPath,
				VerifyThreshold: conf.VerifyThreshold,
				HashAlg:         conf.HashAlg,
			},
			File: outputFile,
			Log:  commandLog,
		}
		if err := ctx.VerifyFile(); err == nil {
			signedIsValid = true
		} else {
			commandLog.Printf("Already signed zone does not verify: %s", err)
		}
	} else {
		commandLog.Printf("Cannot open output file: %s", err)
	}
	signedIsObsolete := signedModDate.Before(zoneModDate)
	commandLog.Printf("Signed file exists? %t | Signed file is valid? %t | Signed file is obsolete? %t", signedExists, signedIsValid, signedIsObsolete)
	return !signedExists || !signedIsValid || signedIsObsolete
}
