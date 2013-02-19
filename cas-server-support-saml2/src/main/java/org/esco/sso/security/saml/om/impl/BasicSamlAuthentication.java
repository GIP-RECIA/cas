/**
 * 
 */
package org.esco.sso.security.saml.om.impl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.esco.sso.security.saml.exception.SamlSecurityException;
import org.esco.sso.security.saml.om.IAuthentication;
import org.joda.time.DateTime;

/**
 * Basic implementation of a ISamlAuthentication.
 * This object is immutable after a call on locked() method.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class BasicSamlAuthentication implements IAuthentication {

	/** Is this object locked (immutable) ?. */
	private boolean locked = false;

	/** IdP Authentication instant. */
	private DateTime authenticationInstant;

	/** IdP subject ID. */
	private String subjectId;

	/** IdP session id. */
	private String sessionIndex;

	/** Subject attributes. */
	private Map<String, List<String>> attributes = new HashMap<String, List<String>>(2);

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder(256);
		sb.append("BasicSamlAuthentication [authenticationInstant=");
		sb.append(this.authenticationInstant);
		sb.append(", subjectId=");
		sb.append(this.subjectId);
		sb.append(", sessionIndex=");
		sb.append(this.sessionIndex);
		sb.append(", attributes=");
		sb.append(this.attributes.toString());
		sb.append("]");

		return  sb.toString();
	}

	@Override
	public DateTime getAuthenticationInstant() {
		return this.authenticationInstant;
	}

	@Override
	public String getSubjectId() {
		return this.subjectId;
	}

	@Override
	public String getSessionIndex() {
		return this.sessionIndex;
	}

	@Override
	public void addAttribute(final String name, final List<String> values)
			throws SamlSecurityException {
		if (this.locked) {
			throw new IllegalAccessError(
					"The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		final List<String> alreadyKnown = this.attributes.get(name);
		if (alreadyKnown != null) {
			throw new SamlSecurityException(String.format(
					"Assertion contained multiple attributes with same name: [%1$s] !", name));
		}

		this.attributes.put(name, values);
	}

	/** Turn the BasicSamlAuthentication immutable. */
	public void lock() {
		this.locked = true;
	}

	@Override
	public List<String> getAttribute(final String name) {
		return this.attributes.get(name);
	}

	@Override
	public Map<String, List<String>> getAttributes() {
		return this.attributes;
	}

	public void setAuthenticationInstant(final DateTime authenticationInstant) {
		if (this.locked) {
			throw new IllegalAccessError(
					"The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		this.authenticationInstant = authenticationInstant;
	}

	public void setSubjectId(final String subjectId) {
		if (this.locked) {
			throw new IllegalAccessError(
					"The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		this.subjectId = subjectId;
	}

	public void setSessionIndex(final String sessionIndex) {
		if (this.locked) {
			throw new IllegalAccessError(
					"The BasicSamlAuthentication is locked ! It cannot be modified !");
		}

		this.sessionIndex = sessionIndex;
	}

}
