package domain_judger

import (
	"log"
	"strings"
)
import "golang.org/x/net/idna"

type Result struct {
	TLDBadReputation         bool
	InnerTLD                 bool
	IncludeMaliciousKeywords bool
	UsePunycode              bool
	CrtshResults             *CrtshResponse
	UseLetsEncrypt           *bool
}

func (r Result) Suspicious() bool {
	if r.TLDBadReputation || r.InnerTLD || r.IncludeMaliciousKeywords || r.UsePunycode {
		return true
	}

	if r.CrtshResults != nil {
		if r.UseLetsEncrypt != nil && *r.UseLetsEncrypt == true {
			return true
		}
	}

	return false
}

var p = idna.New()

func Judge(domain string, checkCert bool) Result {
	ps, err := p.ToASCII(domain)
	if err == nil {
		domain = ps
	}

	result := Result{
		TLDBadReputation:         false,
		InnerTLD:                 false,
		IncludeMaliciousKeywords: false,
		UsePunycode:              false,
	}

	for _, tld := range badTlds {
		if strings.HasSuffix(domain, tld) {
			result.TLDBadReputation = true
			break
		}
	}

	splitDomain := strings.Split(domain, ".")
	removeTld := strings.Join(splitDomain[:len(splitDomain)-1], ".")
	for _, tld := range commonTlds {
		if strings.Contains(removeTld, tld) {
			result.InnerTLD = true
			break
		}
	}

	for _, k := range maliciousKeywords {
		if strings.Contains(domain, k) {
			result.IncludeMaliciousKeywords = true
			break
		}
	}

	if strings.Contains(domain, "xn--") {
		result.UsePunycode = true
	}

	if checkCert {
		resp, err := searchCert(domain)
		if err != nil {
			log.Printf("search error! -> %s", err.Error())
		} else if err == nil {
			if resp != nil {
				result.CrtshResults = resp
				useLetsEncrypt := false

				for _, r := range *resp {
					if r.CommonName == domain || r.CommonName == "*."+domain {
						if strings.Contains(r.IssuerName, "Let's Encrypt") {
							useLetsEncrypt = true
							break
						}
					}
				}

				result.UseLetsEncrypt = &useLetsEncrypt
			}
		}
	}

	return result
}
