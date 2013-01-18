/**
 * 
 */
package org.esco.sso.security.saml;

import javax.servlet.http.HttpServletRequest;

import org.esco.cas.ISaml20Facade;
import org.esco.sso.security.ISpConfig;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.signature.Signature;

/**
 * SAML 2.0 IdP connector to ensure dialog with the IdP.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISaml20SpProcessor {

	/**
	 * Process an incoming SAML 2.0 request.
	 * 
	 * @param request the HttpServletRequest containing the SAML 2.0 request
	 * @return the SAML 2.0 response datas
	 * @throws SamlProcessingException in case of problem during processing.
	 */
	SamlResponseData processSaml20IncomingRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlProcessingException;

	/**
	 * Process an incoming SAML 2.0 Single Logout request.
	 * 
	 * @param request the HttpServletRequest containing the SAML 2.0 response
	 * @return the SAML 2.0 response datas
	 * @throws SamlProcessingException in case of problem during processing.
	 */
	SamlResponseData processSaml20IncomingSingleLogoutRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlProcessingException;

	/**
	 * Find the SAML 2.0 IdP Connector corresponding to an entity Id.
	 * 
	 * @param idpEntityId the EntityId of the connector
	 * @return the SAML 2.0 IdP connector attached
	 */
	ISaml20IdpConnector findSaml20IdpConnectorToUse(String idpEntityId);

	/**
	 * Encode a SAML 2.0 signable object.
	 * 
	 * @param binding the SAML binding to use
	 * @param samlObject the SAML 2.0 object
	 * @return an ecoded and signed object.
	 */
	String encodeSamlObject(SamlBindingEnum binding, SignableSAMLObject samlObject);

	/**
	 * Retrieve a previously cached SAML 2.0 response which was a
	 * response to a request.
	 * 
	 * @param relayState opaque reference to state information
	 * @return the SAML 2.0 response datas
	 */
	SamlResponseData getCachedSaml20Response(String relayState);

	/**
	 * Store a SAML request which was built on this SP for a later use.
	 * 
	 * @param requestData the request to store
	 */
	void storeSamlRequestDataInCache(final SamlRequestData requestData);

	/**
	 * Retrieve the SAML 2.0 Facade.
	 * 
	 * @return the SAML 2.0 facade
	 */
	ISaml20Facade getSaml20Facade();

	/**
	 * Retrieve the SP config attached to this connector.
	 * 
	 * @return the SP configuration
	 */
	ISpConfig getSpConfig();

	/**
	 * Retrieve the Decrypter attached to this connector.
	 * 
	 * @return the decrypter
	 */
	Decrypter getDecrypter();

	/**
	 * Sign a SAML Object as builded by this SP.
	 * 
	 * @param signable a Signable SAML object
	 * @return the signature witch signed the object
	 */
	Signature signSamlObject(SignableSAMLObject signable);
}
