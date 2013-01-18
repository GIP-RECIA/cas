/**
 * 
 */
package org.esco.cas.impl;

import java.io.Serializable;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.esco.sso.security.saml.opensaml.OpenSamlHelper;
import org.opensaml.saml2.core.Subject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.UnmarshallingException;
import org.springframework.util.StringUtils;

/**
 * Informations about SAML 2.0 Authentication.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlAuthInfo implements Serializable {

	/** SVUID. */
	private static final long serialVersionUID = 6429165239146373686L;

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(SamlAuthInfo.class);

	/** Credentials used for authentication. */
	private ISaml20Credentials authCredentials;

	/** Entity Id of the IdP used for authentication. */
	private String idpEntityId;

	/** SAML 2.0 Subject sent by the IdP. */
	private transient Subject idpSubject;

	/** SAML 2.0 Subject in XML form (marshalled). */
	private String marshalledIdpSubject;

	/** IdP session index. */
	private String sessionIndex;

	public Subject getIdpSubject() {
		if ((this.idpSubject == null) && StringUtils.hasText(this.marshalledIdpSubject)) {
			try {
				this.idpSubject = (Subject) OpenSamlHelper.unmarshallXmlObject(Subject.TYPE_NAME,
						this.marshalledIdpSubject);
			} catch (UnmarshallingException e) {
				SamlAuthInfo.LOGGER.error("Error while unmarshalling authneticated SAML 2.0 Subject !", e);
			}
		}

		return this.idpSubject;
	}

	public void setIdpSubject(final Subject idpSubject) {
		this.idpSubject = idpSubject;

		if (idpSubject != null) {
			try {
				idpSubject.detach();
				this.marshalledIdpSubject = OpenSamlHelper.marshallXmlObject(idpSubject);
			} catch (MarshallingException e) {
				SamlAuthInfo.LOGGER.error("Error while marshalling authneticated SAML 2.0 Subject !", e);
			}
		}
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
