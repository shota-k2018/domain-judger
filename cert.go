package domain_judger

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type CrtshResponse []CrtshResponseRow
type CrtshResponseRow struct {
	IssuerCAID     int64  `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

const (
	crtshUrl = "https://crt.sh/?q=%s&output=json"
)

func searchCert(domain string) (*CrtshResponse, error) {
	resp, err := http.Get(fmt.Sprintf(crtshUrl, domain))
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var cr CrtshResponse
	if err := json.Unmarshal(body, &cr); err != nil {
		return nil, err
	}

	return &cr, nil
}
