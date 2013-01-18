/**
 * 
 */
package org.esco.sso.security.saml;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.Subject;


/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SamlResponseData implements Serializable {

	/** SVUID. */
	private static final long serialVersionUID = 7456763384425607618L;

	private String id;

	private String inResponseToId;

	private String samlResponse;

	private SamlRequestData originalRequestData;

	private Map<String, List<String>> attributes = new HashMap<String, List<String>>();

	private transient Subject samlSubject;

	/** The IdP session index. */
	private String sessionIndex;

	public String getId() {
		return this.id;
	}

	public void setId(final String id) {
		this.id = id;
	}

	public String getSamlResponse() {
		return this.samlResponse;
	}

	public void setSamlResponse(final String samlResponse) {
		this.samlResponse = samlResponse;
	}

	public SamlRequestData getOriginalRequestData() {
		return this.originalRequestData;
	}

	public void setOriginalRequestData(final SamlRequestData authnRequestData) {
		this.originalRequestData = authnRequestData;
	}

	public void setAttributes(final Map<String, List<String>> attributes) {
		this.attributes = attributes;
	}

	public List<String> getAttribute(final String key) {
		return this.attributes.get(key);
	}

	public String getInResponseToId() {
		return this.inResponseToId;
	}

	public void setInResponseToId(final String inResponseToId) {
		this.inResponseToId = inResponseToId;
	}

	public Subject getSamlSubject() {
		return this.samlSubject;
	}

	public void setSamlSubject(final Subject samlSubject) {
		this.samlSubject = samlSubject;
	}

	public String getSessionIndex() {
		return this.sessionIndex;
	}

	public void setSessionIndex(final String sessionIndex) {
		this.sessionIndex = sessionIndex;
	}

}
