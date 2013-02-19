/**
 * 
 */
package org.esco.sso.security.saml.om;

import java.io.Serializable;

import org.esco.sso.security.saml.query.IQuery;

/**
 * Represent SAML Data.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public interface ISamlData extends Serializable {

	/**
	 * The SAML query (Request, Response, ...).
	 * @return
	 */
	IQuery getSamlQuery();

	/**
	 * Unencoded (clear) request message.
	 * @return Encoded request.
	 */
	String getSamlMessage();

	/**
	 * Relay state.
	 * @return Relay state.
	 */
	String getRelayState();

	/**
	 * Endpoint URL for request.
	 * @return Endpoint URL for request.
	 */
	String getEndpointUrl();
}
