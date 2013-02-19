/**
 * 
 */
package org.esco.sso.security.saml.query.impl;

import java.util.List;

import org.esco.sso.security.saml.om.IAuthentication;
import org.esco.sso.security.saml.om.IResponse;

/**
 * SAML Authn Response to a SAML Authn Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class QueryAuthnResponse extends SamlQuery implements IResponse {

	/** Svuid. */
	private static final long serialVersionUID = 381464903804175698L;

	/** Authentications embeded in the response. */
	private List<IAuthentication> samlAuthentications;

	private String inResponseToId;

	private QueryAuthnRequest originalRequest;

	public QueryAuthnResponse(final String id) {
		super(id);
	}

	@Override
	public String getInResponseToId() {
		return this.inResponseToId;
	}

	@Override
	public QueryAuthnRequest getOriginalRequest() {
		return this.originalRequest;
	}

	public List<IAuthentication> getSamlAuthentications() {
		return this.samlAuthentications;
	}

	public void setOriginalRequest(final QueryAuthnRequest originalRequest) {
		this.originalRequest = originalRequest;
	}

	public void setInResponseToId(final String inResponseToId) {
		this.inResponseToId = inResponseToId;
	}

	public void setSamlAuthentications(final List<IAuthentication> authns) {
		this.samlAuthentications = authns;
	}

}
