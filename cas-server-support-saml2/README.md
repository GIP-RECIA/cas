Plugin SAML 2.0 for CAS

When integrate in the CAS workflow, this plugin allow the CAS server to be seen as a 
SAML 2.0 Service Provider.

The users may authenticate themselves from the CAS server, or from a distant Identity
Provider like Shibboleth.

For now, all SAML 2.0 protocol is not implemented.
Here a list of SAML 2.0 features currently supported :
- Authentication Request Protocol (currently used)
- Single Logout Protocol
- POST binding
- Redirect binding

We thought the next feature need to be the Artifact Resolution Protocol.
