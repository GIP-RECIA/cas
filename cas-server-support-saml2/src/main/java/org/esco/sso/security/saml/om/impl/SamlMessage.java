/**
 * 
 */
package org.esco.sso.security.saml.om.impl;

import org.esco.sso.security.saml.om.ISamlData;
import org.esco.sso.security.saml.query.IQuery;

/**
 * Saml message.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class SamlMessage implements ISamlData {

	/** Svuid. */
	private static final long serialVersionUID = 7583934230467679286L;

	/** SAML message representing the request to send. */
	private String samlMessage;

	/** Relay State to send. */
	private String relayState;

	/** Endpoint URL where to send the Request. */
	private String endpointUrl;

	/** Query representation of the message. */
	private IQuery samlQuery;

	@Override
	public String getSamlMessage() {
		return this.samlMessage;
	}

	@Override
	public String getRelayState() {
		return this.relayState;
	}

	@Override
	public String getEndpointUrl() {
		return this.endpointUrl;
	}

	@Override
	public IQuery getSamlQuery() {
		return this.samlQuery;
	}

	public void setSamlQuery(final IQuery samlQuery) {
		this.samlQuery = samlQuery;
	}

	public void setSamlMessage(final String samlMessage) {
		this.samlMessage = samlMessage;
	}

	public void setRelayState(final String relayState) {
		this.relayState = relayState;
	}

	public void setEndpointUrl(final String endpointUrl) {
		this.endpointUrl = endpointUrl;
	}


}
