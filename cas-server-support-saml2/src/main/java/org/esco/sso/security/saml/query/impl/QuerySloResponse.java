/**
 * 
 */
package org.esco.sso.security.saml.query.impl;

import org.esco.sso.security.saml.om.IResponse;

/**
 * SAML SLO Response to a SAML SLO Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QuerySloResponse extends SamlQuery implements IResponse {

	/** Svuid. */
	private static final long serialVersionUID = 99264549059131337L;

	private String inResponseToId;

	private QuerySloRequest originalRequest;

	public QuerySloResponse(final String id) {
		super(id);
	}

	@Override
	public String getInResponseToId() {
		return this.inResponseToId;
	}

	@Override
	public QuerySloRequest getOriginalRequest() {
		return this.originalRequest;
	}

	public void setOriginalRequest(final QuerySloRequest originalRequest) {
		this.originalRequest = originalRequest;
	}

	public void setInResponseToId(final String inResponseToId) {
		this.inResponseToId = inResponseToId;
	}

}
