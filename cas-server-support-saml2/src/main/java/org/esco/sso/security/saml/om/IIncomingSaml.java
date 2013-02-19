/**
 * 
 */
package org.esco.sso.security.saml.om;

/**
 * Interface representing incoming data from outside (an IdP).
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IIncomingSaml extends ISamlData {

	/**
	 * Unencoded (clear) request message.
	 * 
	 * @param samlMessage
	 */
	//void setSamlMessage(String samlMessage);

	/**
	 * Relay state.
	 * 
	 * @param relayState
	 */
	//void setRelayState(String relayState);

	/**
	 * Endpoint URL for request.
	 * 
	 * @param endpointUrl
	 */
	//void setEndpointUrl(String endpointUrl);
}
