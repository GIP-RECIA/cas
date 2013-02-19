/**
 * 
 */
package org.esco.sso.security.saml.query.impl;

import org.esco.sso.security.saml.query.IQuery;

/**
 * Base ISamlQuery implementation.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public abstract class SamlQuery implements IQuery {

	/** Svuid. */
	private static final long serialVersionUID = 8644852271120115445L;

	private String id;

	@Override
	public String getId() {
		return this.id;
	}

	public SamlQuery(final String id) {
		super();
		this.id = id;
	}

}
