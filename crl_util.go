package keyfactor

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/helper/errutil"
	"github.com/hashicorp/vault/sdk/logical"
)

//const kf_revoke_path = "/CMSAPI/Certificates/Revoke"
const kf_revoke_path = "/KeyfactorAPI/Certificates/Revoke"

type revocationInfo struct {
	CertificateBytes  []byte    `json:"certificate_bytes"`
	RevocationTime    int64     `json:"revocation_time"`
	RevocationTimeUTC time.Time `json:"revocation_time_utc"`
}

// Revokes a cert, and tries to be smart about error recovery
func revokeCert(ctx context.Context, b *backend, req *logical.Request, serial string, fromLease bool) (*logical.Response, error) {
	// As this backend is self-contained and this function does not hook into
	// third parties to manage users or resources, if the mount is tainted,
	// revocation doesn't matter anyways -- the CRL that would be written will
	// be immediately blown away by the view being cleared. So we can simply
	// fast path a successful exit.
	if b.System().Tainted() {
		return nil, nil
	}
	b.Logger().Debug("Closing idle connections")
	http.DefaultClient.CloseIdleConnections()

	kfId, err := req.Storage.Get(ctx, "kfId/"+serial) //retrieve the keyfactor certificate ID, keyed by sn here
	if err != nil {
		b.Logger().Error("Unable to retreive Keyfactor certificate ID for cert with serial: "+serial, err)
		return nil, err
	}

	var keyfactorId int
	err = kfId.DecodeJSON(&keyfactorId)

	if err != nil {
		b.Logger().Error("Unable to parse stored certificate ID for cert with serial: "+serial, err)
		return nil, err
	}

	// set up keyfactor api request
	url := config["protocol"] + "://" + config["host"] + kf_revoke_path
	payload := fmt.Sprintf(`{
		"CertificateIds": [
		  %d
		],
		"Reason": 0,
		"Comment": "%s",
		"EffectiveDate": "%s"},
		"CollectionId": 0
	  }`, keyfactorId, "via HashiCorp Vault", time.Now().UTC().String())
	//b.Logger().Debug("Sending revocation request.  payload =  " + payload)
	httpReq, _ := http.NewRequest("POST", url, strings.NewReader(payload))

	httpReq.Header.Add("x-keyfactor-requested-with", "APIClient")
	httpReq.Header.Add("content-type", "application/json")
	httpReq.Header.Add("authorization", "Basic "+config["creds"])

	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		b.Logger().Error("Revoke failed: {{err}}", err)
		return nil, err
	}
	if res.StatusCode != 204 {
		r, _ := ioutil.ReadAll(res.Body)
		b.Logger().Info("revocation failed: server returned" + fmt.Sprint(res.StatusCode))
		b.Logger().Info("error response = " + fmt.Sprint(r))
		return nil, fmt.Errorf("revocation failed: server returned  %s\n ", res.Status)
	}

	defer res.Body.Close()
	_, _ = ioutil.ReadAll(res.Body)

	alreadyRevoked := false
	var revInfo revocationInfo

	revEntry, err := fetchCertBySerial(ctx, req, "revoked/", serial)
	if err != nil {
		switch err.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(err.Error()), nil
		case errutil.InternalError:
			return nil, err
		}
	}
	if revEntry != nil {
		// Set the revocation info to the existing values
		alreadyRevoked = true
		err = revEntry.DecodeJSON(&revInfo)
		if err != nil {
			return nil, fmt.Errorf("error decoding existing revocation info")
		}
	}

	if !alreadyRevoked {
		certEntry, err := fetchCertBySerial(ctx, req, "certs/", serial)
		if err != nil {
			switch err.(type) {
			case errutil.UserError:
				return logical.ErrorResponse(err.Error()), nil
			case errutil.InternalError:
				return nil, err
			}
		}
		if certEntry == nil {
			if fromLease {
				// We can't write to revoked/ or update the CRL anyway because we don't have the cert,
				// and there's no reason to expect this will work on a subsequent
				// retry.  Just give up and let the lease get deleted.
				b.Logger().Warn("expired certificate revoke failed because not found in storage, treating as success", "serial", serial)
				return nil, nil
			}
			return logical.ErrorResponse(fmt.Sprintf("certificate with serial %s not found", serial)), nil
		}
		b.Logger().Info("certEntry key = " + certEntry.Key)
		b.Logger().Info("certEntry value = " + string(certEntry.Value))
		// cert, err := x509.ParseCertificate(certEntry.Value)
		// if err != nil {
		// 	return nil, errwrap.Wrapf("error parsing certificate: {{err}}", err)
		// }
		// if cert == nil {
		// 	return nil, fmt.Errorf("got a nil certificate")
		// }

		// Add a little wiggle room because leases are stored with a second
		// granularity
		// if cert.NotAfter.Before(time.Now().Add(2 * time.Second)) {
		// 	return nil, nil
		// }

		currTime := time.Now()
		revInfo.CertificateBytes = certEntry.Value
		revInfo.RevocationTime = currTime.Unix()
		revInfo.RevocationTimeUTC = currTime.UTC()

		revEntry, err = logical.StorageEntryJSON("revoked/"+normalizeSerial(serial), revInfo)
		if err != nil {
			return nil, fmt.Errorf("error creating revocation entry")
		}

		err = req.Storage.Put(ctx, revEntry)
		if err != nil {
			return nil, fmt.Errorf("error saving revoked certificate to new location")
		}

	}

	// crlErr := buildCRL(ctx, b, req, false)
	// switch crlErr.(type) {
	// case errutil.UserError:
	// 	return logical.ErrorResponse(fmt.Sprintf("Error during CRL building: %s", crlErr)), nil
	// case errutil.InternalError:
	// 	return nil, errwrap.Wrapf("error encountered during CRL building: {{err}}", crlErr)
	// }

	resp := &logical.Response{
		Data: map[string]interface{}{
			"revocation_time": revInfo.RevocationTime,
		},
	}
	if !revInfo.RevocationTimeUTC.IsZero() {
		resp.Data["revocation_time_rfc3339"] = revInfo.RevocationTimeUTC.Format(time.RFC3339Nano)
	}
	return resp, nil
}
