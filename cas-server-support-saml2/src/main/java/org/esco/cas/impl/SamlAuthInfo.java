/**
 * 
 */
package org.esco.cas.impl;

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.principal.ISaml20Credentials;

/**
 * Informations about SAML 2.0 Authentication.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlAuthInfo implements Serializable {

	/** SVUID. */
	private static final long serialVersionUID = -2408640620469852696L;

	/** Logger. */
	@SuppressWarnings("unused")
	private static final Log LOGGER = LogFactory.getLog(SamlAuthInfo.class);

	/** Credentials used for authentication. */
	private ISaml20Credentials authCredentials;

	/** Entity Id of the IdP used for authentication. */
	private String idpEntityId;

	/** SAML 2.0 Subject sent by the IdP. */
	private String subjectId;

	/** IdP session index. */
	private String sessionIndex;

	public String getIdpSubject() {
		return this.subjectId;
	}

	public void setIdpSubject(final String subjectId) {
		this.subjectId = subjectId;
	}

	public ISaml20Credentials getAuthCredentials() {
		return this.authCredentials;
	}

	public void setAuthCredentials(final ISaml20Credentials authCredentials) {
		this.authCredentials = authCredentials;
	}

	public String getIdpEntityId() {
		return this.idpEntityId;
	}

	public void setIdpEntityId(final String idpEntityId) {
		this.idpEntityId = idpEntityId;
	}

	public String getSessionIndex() {
		return this.sessionIndex;
	}

	public void setSessionIndex(final String sessionIndex) {
		this.sessionIndex = sessionIndex;
	}

}
