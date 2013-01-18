/**
 * 
 */
package org.esco.sso.security;

import java.io.Serializable;

import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.SamlBuildingException;
import org.esco.sso.security.saml.SamlRequestData;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.core.io.Resource;

/**
 * IdP configuration for display.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IIdpConfig extends Serializable {

	/** Id of the IdP config. */
	String getId();

	/** Description of the IdP. */
	String getDescription();

	/** Picture of the IdP. */
	String getPictureUrl();

	/** SAML 2.0 Connector for the IdP. */
	ISaml20IdpConnector getSaml20IdpConnector();

	/** Register a SAML 2.0 Connector for the IdP. */
	void registerSaml20IdpConnector(ISaml20IdpConnector saml20IdpConnector);

	/**
	 * Build a SAML AuthnRequest for this IdP.
	 * 
	 * @param binding the SAML binding used for this request
	 * @return the SAML 2.0 AuthnRequest
	 */
	SamlRequestData getSamlAuthnRequest(SamlBindingEnum binding);

	/**
	 * Build a SAML Logout Request for this IdP.
	 * 
	 * @param binding the SAML binding used for this request
	 * @return the SAML 2.0 Logout Request
	 * @throws SamlBuildingException
	 */
	SamlRequestData getSamlSingleLogoutRequest(SamlBindingEnum binding) throws SamlBuildingException;

	/**
	 * Access to the global wayf configuration.
	 * 
	 * @return the global wayf configuration
	 */
	IWayfConfig getWayfConfig();

	/**
	 * Register the global wayf configuration.
	 * 
	 * @param wayfConfig the global wayf configuration
	 */
	void registerWayfConfig(IWayfConfig wayfConfig);

	/**
	 * Retrieve the IdP Entity Id.
	 * 
	 * @return the IdP Entity Id
	 */
	String getIdpEntityId();

	/**
	 * Time window in ms durint which the request are valids
	 * (by default 300000ms means requests are valid +-300000ms).
	 * 
	 * @return the time validity window
	 */
	public long getTimeValidityWindow();

	/**
	 * Retrieve the binding which must be used to send SAML requests.
	 * 
	 * @return the binding used to send SAML requests
	 */
	SamlBindingEnum getRequestBinding();

	boolean isForceAuthentication();

	Resource getIdpMetadata();

	SamlBindingEnum getResponseBinding();

	Integer getAttributeConsumingServiceIndex();

	SignatureTrustEngine getSignatureTrustEngine();

	String getIdpSsoEndpointUrl(SamlBindingEnum binding);

	String getIdpSloEndpointUrl(SamlBindingEnum binding);
}
