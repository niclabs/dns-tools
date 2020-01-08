package signer

import (
/*
        "encoding/base64"
        "encoding/binary"
        "fmt"
        "github.com/miekg/dns"
        "io"
        "log"
        "sort"
        "time"
*/
)

type FileKey struct {
  ZSKfile	string
  KSKfile	string
  Log    *log.Logger          // Logger (for output)
}


