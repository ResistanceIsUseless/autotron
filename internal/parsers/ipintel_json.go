package parsers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/resistanceisuseless/autotron/internal/graph"
)

// ipintelJSONParser handles the custom ipintel tool's JSON output.
// ipintel enriches IP nodes with ASN, organization, geolocation,
// and network provider metadata.
type ipintelJSONParser struct{}

func init() {
	Register(&ipintelJSONParser{})
}

func (p *ipintelJSONParser) Name() string { return "ipintel_json" }

// ipintelOutput represents the expected JSON output from ipintel.
type ipintelOutput struct {
	IP      string        `json:"ip"`
	ASN     *ipintelASN   `json:"asn"`
	Geo     *ipintelGeo   `json:"geo"`
	Network *ipintelNet   `json:"network"`
	Abuse   *ipintelAbuse `json:"abuse"`
}

type ipintelASN struct {
	Number int    `json:"number"`
	Name   string `json:"name"`
	Org    string `json:"org"`
}

type ipintelGeo struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

type ipintelNet struct {
	CIDR     string `json:"cidr"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Type     string `json:"type"` // hosting, isp, education, etc.
}

type ipintelAbuse struct {
	Email   string `json:"email"`
	Contact string `json:"contact"`
}

func (p *ipintelJSONParser) Parse(ctx context.Context, trigger graph.Node, stdout io.Reader, stderr io.Reader) (Result, error) {
	var output ipintelOutput
	if err := json.NewDecoder(stdout).Decode(&output); err != nil {
		return Result{}, fmt.Errorf("decode ipintel JSON: %w", err)
	}

	// This parser enriches the triggering Subdomain node with IP intelligence
	// metadata. The IP intel data is stored as properties on the Subdomain.
	props := map[string]any{}

	if output.IP != "" {
		props["ipintel_ip"] = output.IP
	}

	if output.ASN != nil {
		props["asn_number"] = output.ASN.Number
		props["asn_name"] = output.ASN.Name
		props["asn_org"] = output.ASN.Org
	}

	if output.Geo != nil {
		props["country"] = output.Geo.Country
		props["country_code"] = output.Geo.CountryCode
		props["region"] = output.Geo.Region
		props["city"] = output.Geo.City
		props["latitude"] = output.Geo.Latitude
		props["longitude"] = output.Geo.Longitude
	}

	if output.Network != nil {
		props["net_cidr"] = output.Network.CIDR
		props["net_name"] = output.Network.Name
		props["net_provider"] = output.Network.Provider
		props["net_type"] = output.Network.Type
	}

	if output.Abuse != nil {
		props["abuse_email"] = output.Abuse.Email
		props["abuse_contact"] = output.Abuse.Contact
	}

	// Enrich the triggering Subdomain node.
	props["fqdn"] = trigger.PrimaryKey

	var result Result
	result.Nodes = append(result.Nodes, graph.Node{
		Type:       graph.NodeSubdomain,
		PrimaryKey: trigger.PrimaryKey,
		Props:      props,
	})

	return result, nil
}
