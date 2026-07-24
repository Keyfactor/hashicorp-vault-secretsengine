- 1.5.0
  - Added automatic and on-demand cleanup ("tidy") of expired certificates from local storage, via the new `tidy` and `tidy/status` endpoints and the `tidy_enabled`, `tidy_interval`, and `tidy_safety_buffer` configuration settings.
  - Certificate listing (`vault list <mount>/certs`) now includes the common name alongside each serial number.
  - Reading a certificate (`vault read <mount>/certs/<serial>`) now returns the serial number, common name, certificate content, submitted metadata, and expiration date.
  - Certificate metadata submitted when issuing or signing is now stored locally and echoed back in the issue and sign responses.
  - Fixed several potential nil-pointer panics that could occur when the Command API returned an error or an empty response.
  - Fixed concurrency issues where the cached configuration and API client could be mutated while only a read lock was held.
  - Deleting the configuration now clears the in-memory cache, so subsequent operations no longer use the deleted configuration.
  - Fixed certificate revocation failing with "failed to decompress JSON: lz4: bad magic number" for certificates whose Keyfactor ID begins with a character matching a Vault compression canary; the stored ID is now decoded directly rather than through the compression-aware decoder.
  - Fixed the sign path so that provided DNS SANs are validated against the role (previously this check was inadvertently skipped).
  - Fixed certificate metadata JSON validation being silently bypassed.
  - Corrected allowed-domain matching to prevent a subdomain-suffix bypass (for example, "evilexample.com" is no longer treated as matching "example.com").
  - The access token is now masked in the configuration read output.
  - Added a unit test suite and corrected several documentation inaccuracies.

- 1.4.2
  - Updated the Hashicorp SDK libraries
  - Incorporated the Keyfactor GO SDK for authentication and interaction with the Command API
  
- 1.4.1
  - Updated CA and CA chain retreival to work for CA's hosted outside of Command (EJBCA)
  - Updated Keyfactor Client library to 1.2.0
  - Now passing scopes and audience along with oAuth token request.
  - including dns_sans, ip_sans and metadata along with pre-generated csr sign requests
  
- 1.4.0
  - Added support for oAuth2 authentication to Keyfactor Command.
  - Included the ability to specify CA and Template via command parameters
  - Included the ability to pass metadata along with the request

- 1.3.1 
  - Fix for issue where plugin was not enforcing plugin-side role limitations for AllowedDomains and AllowSubDomains, and was relying exclusively on the certificate template for these values.

- 1.3.0
  - Fix for double encoding certificates when viewed in the terminal.

- 1.2.0
  - Updated the plugin to use it's own internal configuration settings storage per instance.

- 1.1.0
  - added subject parameters to certificate enrollment
  - now defaulting to role values for subject parameters if not provided.

- 1.0.1
  - This release fixes a bug where the CA logical name was not being URL encoded before sending the request to Keyfactor.

- 1.00
  - initial release
