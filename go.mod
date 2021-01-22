module github.com/niclabs/dns-tools

go 1.12

require (
	github.com/miekg/dns v1.1.33
	github.com/miekg/pkcs11 v1.0.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/viper v1.4.0
)

replace github.com/miekg/dns => github.com/niclabs/dns v1.1.37
