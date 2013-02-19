/**
 * 
 */
package org.esco.sso.security.saml.query.impl;

import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IRequestWaitingForResponse;

/**
 * SAML SLO Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QuerySloRequest extends SamlQuery implements IRequestWaitingForResponse {

	/** Svuid. */
	private static final long serialVersionUID = 1081464086973460157L;

	final ISaml20IdpConnector idpConnectorBuilder;

	public QuerySloRequest(final String id, final ISaml20IdpConnector idpConnectorBuilder) {
		super(id);
		this.idpConnectorBuilder = idpConnectorBuilder;
	}

	@Override
	public ISaml20IdpConnector getIdpConnectorBuilder() {
		return this.idpConnectorBuilder;
	}


}
