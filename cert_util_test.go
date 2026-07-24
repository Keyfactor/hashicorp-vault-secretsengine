/*
 *  Copyright 2026 Keyfactor
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
 *  and limitations under the License.
 */

package kfbackend

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"go.mozilla.org/pkcs7"
)

func TestCheckAllowedDomains(t *testing.T) {
	cases := []struct {
		name       string
		allowed    []string
		subdomains bool
		domains    []string
		wantValid  bool
	}{
		{"exact match", []string{"example.com"}, false, []string{"example.com"}, true},
		{"subdomain blocked", []string{"example.com"}, false, []string{"a.example.com"}, false},
		{"subdomain allowed", []string{"example.com"}, true, []string{"a.example.com"}, true},
		{"suffix bypass blocked", []string{"example.com"}, true, []string{"evilexample.com"}, false},
		{"wildcard", []string{"*"}, false, []string{"anything.net"}, true},
		{"empty allowed list", nil, false, []string{"x.com"}, false},
		{"case insensitive", []string{"Example.com"}, false, []string{"EXAMPLE.COM"}, true},
		{"multiple one disallowed", []string{"example.com"}, true, []string{"a.example.com", "b.other.com"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			role := &roleEntry{AllowedDomains: tc.allowed, AllowSubdomains: tc.subdomains}
			valid, err := checkAllowedDomains(role, "testrole", tc.domains)
			if valid != tc.wantValid {
				t.Errorf("valid = %v, want %v (err=%v)", valid, tc.wantValid, err)
			}
			if tc.wantValid && err != nil {
				t.Errorf("unexpected error for allowed case: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Errorf("expected error for disallowed case, got nil")
			}
		})
	}
}

func TestNormalizeSerial(t *testing.T) {
	cases := map[string]string{
		"ab:cd:ef": "AB-CD-EF",
		"AB-CD":    "AB-CD",
		"abcdef":   "ABCDEF",
		"12:Ab:3c": "12-AB-3C",
	}
	for in, want := range cases {
		if got := normalizeSerial(in); got != want {
			t.Errorf("normalizeSerial(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseOtherSANs(t *testing.T) {
	m, err := parseOtherSANs([]string{"1.3.6.1.4.1;utf8:hello"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := m["1.3.6.1.4.1"]; len(got) != 1 || got[0] != "hello" {
		t.Errorf("parsed map = %v", m)
	}

	if _, err := parseOtherSANs([]string{"missing-semicolon"}); err == nil {
		t.Error("expected error for missing semicolon")
	}
	if _, err := parseOtherSANs([]string{"1.2.3;der:xx"}); err == nil {
		t.Error("expected error for unsupported (non-utf8) type")
	}
}

func TestGenerateCSR(t *testing.T) {
	b, _ := getTestBackend(t)

	csrPEM, keyDER, err := b.generateCSR(
		"host.example.com",
		[]string{"10.0.0.1"},
		[]string{"host.example.com", "alt.example.com"},
	)
	if err != nil {
		t.Fatalf("generateCSR err: %v", err)
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("expected a CERTIFICATE REQUEST PEM block, got %v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse generated CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "host.example.com" {
		t.Errorf("CSR CN = %q, want host.example.com", csr.Subject.CommonName)
	}
	if len(csr.DNSNames) != 2 {
		t.Errorf("CSR DNS SANs = %v, want 2 entries", csr.DNSNames)
	}
	if len(csr.IPAddresses) != 1 {
		t.Errorf("CSR IP SANs = %v, want 1 entry", csr.IPAddresses)
	}
	if _, err := x509.ParsePKCS1PrivateKey(keyDER); err != nil {
		t.Errorf("returned private key does not parse as PKCS1: %v", err)
	}
}

func TestConvertBase64P7BtoCertificates(t *testing.T) {
	der := makeTestCertDER(t, "ca.example.com", time.Now().Add(24*time.Hour))

	p7, err := pkcs7.DegenerateCertificate(der)
	if err != nil {
		t.Fatalf("failed to build degenerate PKCS7: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(p7)

	certs, err := ConvertBase64P7BtoCertificates(b64)
	if err != nil {
		t.Fatalf("ConvertBase64P7BtoCertificates err: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}
	if certs[0].Subject.CommonName != "ca.example.com" {
		t.Errorf("certificate CN = %q, want ca.example.com", certs[0].Subject.CommonName)
	}

	if _, err := ConvertBase64P7BtoCertificates("not valid base64 !!!"); err == nil {
		t.Error("expected an error decoding invalid base64")
	}
}
