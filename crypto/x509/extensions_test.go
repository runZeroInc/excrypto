// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/runZeroInc/excrypto/crypto/x509/pkix"
	"github.com/runZeroInc/excrypto/encoding/asn1"
)

var testName = pkix.Name{
	SerialNumber:       "12345",
	CommonName:         "common",
	Country:            []string{"US", "RU"},
	Organization:       []string{"University of Michigan"},
	OrganizationalUnit: []string{"0x21"},
	Locality:           []string{"Ann Arbor"},
	Province:           []string{"Michigan"},
	StreetAddress:      []string{"2260 Hayward St"},
	PostalCode:         []string{"48109"},
	DomainComponent:    nil,
	ExtraNames:         nil,
}

func TestGeneralNamesJSON(t *testing.T) {
	tests := []struct {
		gn GeneralNames
	}{
		{
			gn: GeneralNames{
				DirectoryNames: []pkix.Name{testName},
			},
		},
		{
			gn: GeneralNames{
				DNSNames:       []string{"www.censys.io", "zmap.io"},
				EmailAddresses: []string{"test1@censys.io", "test2@censys.io"},
				URIs:           []string{"www.censys.io", "censys.io"},
			},
		},
		{
			gn: GeneralNames{
				DirectoryNames: []pkix.Name{testName},
				DNSNames:       []string{"www.censys.io", "censys.singles", "zmap.io"},
				EDIPartyNames: []pkix.EDIPartyName{
					{
						NameAssigner: "test1",
						PartyName:    "test2",
					},
					{
						NameAssigner: "test3",
						PartyName:    "test4",
					},
				},
				EmailAddresses: []string{"test1@censys.io", "test2@censys.io"},
				IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1)},
				OtherNames: []pkix.OtherName{
					{
						TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 28},
						Value:  asn1.RawValue{},
					},
					{
						TypeID: asn1.ObjectIdentifier{1, 2, 840, 10008, 1, 2, 4, 52},
						Value:  asn1.RawValue{},
					},
				},
				RegisteredIDs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 28},
					{1, 2, 840, 10008, 1, 2, 4, 52},
				},
				URIs: []string{"www.censys.io", "censys.singles", "zmap.io"},
			},
		},
	}
	for i, test := range tests {
		j, err := json.Marshal(&test.gn)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
			continue
		}
		var backToGN GeneralNames
		err = json.Unmarshal(j, &backToGN)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
			continue
		}
		for _, e := range backToGN.DirectoryNames {
			if !containsName(test.gn.DirectoryNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToGN.DNSNames {
			if !containsString(test.gn.DNSNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToGN.EDIPartyNames {
			if !containsEIDPartyName(test.gn.EDIPartyNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToGN.EmailAddresses {
			if !containsString(test.gn.EmailAddresses, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToGN.IPAddresses {
			if !containsIP(test.gn.IPAddresses, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToGN.OtherNames {
			if !containsOtherName(test.gn.OtherNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToGN.RegisteredIDs {
			if !containsOID(test.gn.RegisteredIDs, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToGN.URIs {
			if !containsString(test.gn.URIs, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
	}
}

func containsIP(s []net.IP, e net.IP) bool {
	for _, a := range s {
		if a.Equal(e) {
			return true
		}
	}
	return false
}

func containsOID(s []asn1.ObjectIdentifier, e asn1.ObjectIdentifier) bool {
	for _, a := range s {
		if a.Equal(e) {
			return true
		}
	}
	return false
}

func containsString(s []string, e string) bool {
	for _, a := range s {
		if strings.Compare(a, e) == 0 {
			return true
		}
	}
	return false
}

func containsName(s []pkix.Name, e pkix.Name) bool {
	eStr := e.String()
	for _, a := range s {
		if strings.Compare(a.String(), eStr) == 0 {
			return true
		}
	}
	return false
}

func containsOtherName(s []pkix.OtherName, e pkix.OtherName) bool {
	for _, a := range s {
		if a.TypeID.Equal(e.TypeID) &&
			bytes.Equal(a.Value.Bytes, a.Value.Bytes) {
			return true
		}
	}
	return false
}

func containsEIDPartyName(s []pkix.EDIPartyName, e pkix.EDIPartyName) bool {
	for _, a := range s {
		if strings.Compare(a.NameAssigner, e.NameAssigner) == 0 &&
			strings.Compare(a.PartyName, e.PartyName) == 0 {
			return true
		}
	}
	return false
}

func TestNameConstraintJSON(t *testing.T) {
	tests := []struct {
		nc NameConstraints
	}{
		{
			nc: NameConstraints{
				ExcludedDNSDomains: []string{
					"censys.singles",
				},
				PermittedDirectoryNames: []pkix.Name{
					testName,
				},
			},
		},
		{
			nc: NameConstraints{
				PermittedDNSDomains: []string{
					"censys.io",
					"censys.singles",
				},
				PermittedEmailAddresses: []string{
					"test1@censys.io",
					"test2@censys.io",
				},
				PermittedURIDomains: []string{
					"http://www.example.com/foo/bar.html",
				},
				PermittedIPRanges: []*net.IPNet{
					{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(0, 0, 0, 0)},
					{IP: net.IPv4(127, 0, 0, 2), Mask: net.IPv4Mask(0, 0, 0, 0)},
				},
				PermittedDirectoryNames: []pkix.Name{
					testName,
				},
				PermittedEdiPartyNames: []pkix.EDIPartyName{
					{
						NameAssigner: "test1",
						PartyName:    "test2",
					},
					{
						NameAssigner: "test3",
						PartyName:    "test4",
					},
				},
				PermittedRegisteredIDs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 28},
					{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 29},
				},
				ExcludedEmailAddresses: []string{
					"test1@censys.io",
					"test2@censys.io",
				},
				ExcludedDNSDomains: []string{
					"censys.io",
					"censys.singles",
				},
				ExcludedIPRanges: []*net.IPNet{
					{IP: net.IPv4(127, 0, 0, 1), Mask: net.IPv4Mask(0, 0, 0, 0)},
					{IP: net.IPv4(127, 0, 0, 2), Mask: net.IPv4Mask(0, 0, 0, 0)},
				},
				ExcludedDirectoryNames: []pkix.Name{
					testName,
				},
				ExcludedEdiPartyNames: []pkix.EDIPartyName{
					{
						NameAssigner: "test1",
						PartyName:    "test2",
					},
					{
						NameAssigner: "test3",
						PartyName:    "test4",
					},
				},
				ExcludedRegisteredIDs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 28},
					{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 29},
				},
			},
		},
	}
	for i, test := range tests {
		j, err := json.Marshal(&test.nc)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
			continue
		}
		var backToNC NameConstraints
		err = json.Unmarshal(j, &backToNC)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
			continue
		}

		for _, e := range backToNC.PermittedDNSDomains {
			if !containsString(test.nc.PermittedDNSDomains, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.PermittedEmailAddresses {
			if !containsString(test.nc.PermittedEmailAddresses, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.PermittedURIDomains {
			if !containsString(test.nc.PermittedURIDomains, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.PermittedIPRanges {
			if !containsNetIP(test.nc.PermittedIPRanges, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.PermittedDirectoryNames {
			if !containspkixName(test.nc.PermittedDirectoryNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.PermittedEdiPartyNames {
			if !containsGeneralSubtreeEDI(test.nc.PermittedEdiPartyNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.PermittedRegisteredIDs {
			if !containsGeneralSubtreeOID(test.nc.PermittedRegisteredIDs, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.ExcludedDNSDomains {
			if !containsString(test.nc.ExcludedDNSDomains, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.ExcludedEmailAddresses {
			if !containsString(test.nc.ExcludedEmailAddresses, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.ExcludedURIDomains {
			if !containsString(test.nc.ExcludedURIDomains, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.ExcludedIPRanges {
			if !containsNetIP(test.nc.ExcludedIPRanges, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.ExcludedDirectoryNames {
			if !containspkixName(test.nc.ExcludedDirectoryNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.ExcludedEdiPartyNames {
			if !containsGeneralSubtreeEDI(test.nc.ExcludedEdiPartyNames, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToNC.ExcludedRegisteredIDs {
			if !containsGeneralSubtreeOID(test.nc.ExcludedRegisteredIDs, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
	}
}

func containsNetIP(s []*net.IPNet, e *net.IPNet) bool {
	for _, a := range s {
		if a.Contains(e.IP) {
			return true
		}
	}
	return false
}

func containsGeneralSubtreeEDI(s []pkix.EDIPartyName, e pkix.EDIPartyName) bool {
	for _, a := range s {
		if strings.Compare(a.NameAssigner, e.NameAssigner) == 0 &&
			strings.Compare(a.PartyName, e.PartyName) == 0 {
			return true
		}
	}
	return false
}

func containspkixName(s []pkix.Name, e pkix.Name) bool {
	for _, a := range s {
		if strings.Compare(a.String(), e.String()) == 0 {
			return true
		}
	}
	return false
}

func containsGeneralSubtreeOID(s []asn1.ObjectIdentifier, e asn1.ObjectIdentifier) bool {
	for _, a := range s {
		if a.Equal(e) {
			return true
		}
	}
	return false
}

func TestValidationLevelJSON(t *testing.T) {
	tests := []struct {
		in  CertValidationLevel
		out string
	}{
		{
			in:  UnknownValidationLevel,
			out: `"unknown"`,
		},
		{
			in:  DV,
			out: `"DV"`,
		},
		{
			in:  OV,
			out: `"OV"`,
		},
		{
			in:  EV,
			out: `"EV"`,
		},
		{
			in:  1234,
			out: `"unknown"`,
		},
		{
			in:  -1,
			out: `"unknown"`,
		},
	}
	for _, test := range tests {
		b, err := json.Marshal(&test.in)
		if err != nil {
			t.Errorf("%s", err)
			continue
		}
		if s := string(b); test.out != s {
			t.Errorf("got %s, wanted %s", s, test.out)
			continue
		}
	}
}

func TestExtendedKeyUsageExtensionJSON(t *testing.T) {
	tests := []struct {
		ek ExtendedKeyUsageExtension
	}{
		{
			ek: ExtendedKeyUsageExtension{
				Known: []ExtKeyUsage{
					ExtKeyUsageServerAuth,
				},
			},
		},
		{
			ek: ExtendedKeyUsageExtension{
				Known: []ExtKeyUsage{
					ExtKeyUsageServerAuth,
					ExtKeyUsageCodeSigning,
				},
				Unknown: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 28},
					{1, 3, 6, 1, 4, 1, 1466, 115, 121, 1, 29},
				},
			},
		},
	}
	for i, test := range tests {
		j, err := json.Marshal(&test.ek)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
			continue
		}
		var backToEK ExtendedKeyUsageExtension
		err = json.Unmarshal(j, &backToEK)
		if err != nil {
			t.Errorf("%d: %s", i, err.Error())
			continue
		}
		for _, e := range backToEK.Known {
			if !containsExtKeyUsage(test.ek.Known, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
		for _, e := range backToEK.Unknown {
			if !containsOID(test.ek.Unknown, e) {
				t.Errorf("%d: JSON Unmarshal did not preserve all values", i)
			}
		}
	}
}

func containsExtKeyUsage(s []ExtKeyUsage, e ExtKeyUsage) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func TestTorServiceDescriptorHashJSON(t *testing.T) {
	testHash := CertificateFingerprint("here is the hash")

	descs := []*TorServiceDescriptorHash{
		{
			Onion: "https://zmap.onion",
			Algorithm: pkix.AlgorithmIdentifier{
				Algorithm: oidSHA256,
			},
			AlgorithmName: "SHA256",
			Hash:          testHash,
			HashBits:      256,
		},
	}

	expectedJSON := fmt.Sprintf(
		`[{"onion":"https://zmap.onion","algorithm_name":"SHA256","hash":%q,"hash_bits":256}]`,
		testHash.Hex())

	out, err := json.Marshal(descs)
	if err != nil {
		t.Errorf("expected no marshal err, got %v", err)
	}
	if outStr := string(out); outStr != expectedJSON {
		t.Errorf("expected JSON %q got %q\n", expectedJSON, outStr)
	}
}
