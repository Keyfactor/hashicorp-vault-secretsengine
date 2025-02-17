- 1.4.1
  - Updated Keyfactor Client library to 1.2.0
  - Now passing scopes and audience along with oAuth token request.
  
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
