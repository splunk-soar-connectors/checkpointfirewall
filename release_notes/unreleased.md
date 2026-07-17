**Unreleased**

* - Enabled TLS server-certificate verification by default for Check Point Management API requests.
* - Stored the Check Point session ID under a platform-redacted state key to prevent spawn-log exposure.
* - Encrypted persisted Check Point Management API session IDs and discarded legacy cleartext state.
* - Removed VPN shared secrets from add-user action results before persistence.
* - Validated update-group-members operations case-insensitively and rejected values that could replace all membership.
* - Waited for block and unblock policy-installation tasks and failed actions whose tasks time out or do not succeed.
