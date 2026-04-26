// Copyright 2026 The runZero contributors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONUnmarshalReturnsErrors(t *testing.T) {
	t.Run("ClientAuthType", func(t *testing.T) {
		var auth ClientAuthType
		err := json.Unmarshal([]byte(`"NoClientCert"`), &auth)
		if err == nil || !strings.Contains(err.Error(), "ClientAuthType JSON unmarshaling is not implemented") {
			t.Fatalf("json.Unmarshal(ClientAuthType) error = %v", err)
		}
	})

	t.Run("Config", func(t *testing.T) {
		var config Config
		err := json.Unmarshal([]byte(`{}`), &config)
		if err == nil || !strings.Contains(err.Error(), "Config JSON unmarshaling is not implemented") {
			t.Fatalf("json.Unmarshal(Config) error = %v", err)
		}
	})
}
