# Plugin SAML 2.0 for CAS
=======================

## Descrtiption

When integrate in the CAS workflow, this plugin allow the CAS server to be seen as a SAML 2.0 Service Provider.

The users may authenticate themselves from the CAS server, or from a distant Identity Provider like Shibboleth IdP.



## How it works

### The WAYF

In the CAS workflow, we introduce a new view called WAYF (Where Are You From ?) which ask the user for an organization which will be able to authenticate him. This view will decide which SAML 2.0 IdP to contact, and send it an Authentication Request. The user is able to choose CAS itself for his authentication which can be seen has a faked IdP, the CAS workflow is then the standard one.

### The IdP Connector

When an IdP is selected, the correspondant IdP Connector is used to build a SAML request to the IdP. We cache the parameters present in the HTTP request like "service". Eventually, we send the SAML Request to the IdP.

### The Servlet Filter

We add a Servlet Filter which will intercept SAML HTTP requests, process it and modify the HTTPServletRequest to add previously cached parameters from the original CAS HTTP request.

### The SP Processor

It's responsible for caching sent SAML requests, processing incoming SAML requests, validating, checking security,...

## Implemented for now

For now, all SAML 2.0 protocols are not implemented yet. Here a list of SAML 2.0 features currently supported :

Authentication Request Protocol
Single Logout Protocol
HTTP-POST binding
HTTP-Redirect binding
We thought the next feature we need to implement will be the HTTP-Artifact Resolution Protocol with it's binding.