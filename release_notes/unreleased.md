**Unreleased**

* - Enabled TLS server-certificate verification by default for Check Point Management API requests.
* - Stored the Check Point session ID under a platform-redacted state key to prevent spawn-log exposure.
* - Encrypted persisted Check Point Management API session IDs and discarded legacy cleartext state.
