// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkix

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNameString(t *testing.T) {
	tests := []struct {
		name     Name
		expected string
		legacy   string
	}{
		{
			name:     Name{},
			expected: "",
			legacy:   "",
		},
		{
			name: Name{
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
				ExtraNames:         []AttributeTypeAndValue{{Type: oidCommonName, Value: "name"}, {Type: oidSerialNumber, Value: "67890"}},
			},
			expected: "SERIALNUMBER=67890,CN=name,C=US+C=RU,POSTALCODE=48109,ST=Michigan,L=Ann Arbor,STREET=2260 Hayward St,O=University of Michigan,OU=0x21",
			legacy:   "SERIALNUMBER=67890,CN=name,C=US+C=RU,POSTALCODE=48109,ST=Michigan,L=Ann Arbor,STREET=2260 Hayward St,O=University of Michigan,OU=0x21",
		},
		{
			name: Name{
				SerialNumber: "12345",
				CommonName:   "common",
				PostalCode:   []string{"48109"},
				OriginalRDNS: RDNSequence{
					[]AttributeTypeAndValue{
						{Type: oidPostalCode, Value: "48109"},
						{Type: oidSerialNumber, Value: "12345"},
						{Type: oidCommonName, Value: "common"},
						{Type: oidGivenName, Value: "given"},
						{Type: oidDomainComponent, Value: "domain"},
						{Type: oidDNEmailAddress, Value: "user@dn.com"},
						{Type: oidJurisdictionLocality, Value: "Locality"},
						{Type: oidJurisdictionProvince, Value: "Prov"},
						{Type: oidJurisdictionCountry, Value: "Canada"},
						{Type: oidOrganizationID, Value: "QWACS"},
					},
				},
			},
			expected: "POSTALCODE=48109+SERIALNUMBER=12345+CN=common+2.5.4.42=given+0.9.2342.19200300.100.1.25=domain+1.2.840.113549.1.9.1=user@dn.com+1.3.6.1.4.1.311.60.2.1.1=Locality+1.3.6.1.4.1.311.60.2.1.2=Prov+1.3.6.1.4.1.311.60.2.1.3=Canada+2.5.4.97=QWACS",
			legacy:   "POSTALCODE=48109+SERIALNUMBER=12345+CN=common+2.5.4.42=given+0.9.2342.19200300.100.1.25=domain+1.2.840.113549.1.9.1=user@dn.com+1.3.6.1.4.1.311.60.2.1.1=Locality+1.3.6.1.4.1.311.60.2.1.2=Prov+1.3.6.1.4.1.311.60.2.1.3=Canada+2.5.4.97=QWACS",
		},
	}
	for _, test := range tests {
		s := test.name.String()
		assert.Equal(t, test.expected, s)
	}
	LegacyNameString = true
	for _, test := range tests {
		s := test.name.String()
		assert.Equal(t, test.legacy, s)
	}
	LegacyNameString = false
}
