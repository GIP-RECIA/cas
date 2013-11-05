# Plugin SAML 2.0 for CAS
=======================

## Descrtiption

When integrate in the CAS workflow, this plugin allow the CAS server to be seen as a SAML 2.0 Service Provider.

The users may authenticate themselves from the CAS server, or from a distant Identity Provider like Shibboleth IdP.

![ScreenShot](https://raw.github.com/GIP-RECIA/cas/feature-saml2/cas-server-support-saml2/global_workflow.png)


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

## Plugin Configuration

For now, we are able to authenticate by retrieving an email in SAML 2.0 Response attributes, retrieve a Principal in LDAP from that email, and authenticate this principal with a configurable list of LDAP filter.
With few sources modifications, it is possible to authenticate principals from any attributes.

The plugin configuration can be done with spring beans files.
Several sample configuration files to put in the CAS webapp are in the sample-config folder.

To be able to configure the plugin, you should be comfortable with shibboleth SP / IdP configuration.

config.properties Add some configuration to CAS server main config file. Mainly SP / IdP EntityId, Metadata, Private keys, Authentication configuration.
wayfConfigContext.xml Configure the content of the WAYF to display.
spAndIdpConfigContext.xml Configure the IdPs and SPs connectors.
cas-servlet-saml2.xml Integration of the module in CAS.
messages_xx.properties Add some messages.
login-webflow.xml Modification of the flow to integrate the saml module.
web.xml Add SAML 2.0 filter to process incoming SAML 2.0 Requests and Responses.

## Plugin Integration

Some example views in sample-view directory : wayfView.jsp
