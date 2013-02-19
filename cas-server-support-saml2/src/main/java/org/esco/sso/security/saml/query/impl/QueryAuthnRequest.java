/**
 * 
 */
package org.esco.sso.security.saml.query.impl;

import java.util.HashMap;
import java.util.Map;

import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IRequestWaitingForResponse;
import org.springframework.util.Assert;

/**
 * SAML Authn Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QueryAuthnRequest extends SamlQuery implements IRequestWaitingForResponse {

	/** Svuid. */
	private static final long serialVersionUID = 2263117124596805999L;

	/** Initial CAS request parameters. */
	private Map<String, String[]> parametersMap;

	/** IdpConnector which build this request. */
	private transient ISaml20IdpConnector idpConnectorBuilder;

	public QueryAuthnRequest(final String id, final ISaml20IdpConnector idpConnectorBuilder,
			final Map<String, String[]> parametersMap) {
		super(id);
		Assert.notNull(idpConnectorBuilder, "No IdP Connector builder provided !");
		Assert.notNull(parametersMap, "No parameters map provided !");

		this.parametersMap = new HashMap<String, String[]>(parametersMap);
		this.idpConnectorBuilder = idpConnectorBuilder;
	}

	@Override
	public ISaml20IdpConnector getIdpConnectorBuilder() {
		return this.idpConnectorBuilder;
	}

	public Map<String, String[]> getParametersMap() {
		return this.parametersMap;
	}

}
