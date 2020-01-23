package signer

import (
	/*
	   "encoding/base64"
	   "encoding/binary"
	   "fmt"
	   "github.com/miekg/dns"
	   "io"
	   "sort"
	   "time"
	*/
	"log"
)

type FileKey struct {
	ZSKfile string
	KSKfile string
	Log     *log.Logger // Logger (for output)
}
