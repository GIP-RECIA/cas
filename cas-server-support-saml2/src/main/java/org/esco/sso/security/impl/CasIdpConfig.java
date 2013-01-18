/**
 * 
 */
package org.esco.sso.security.impl;

import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.IWayfConfig;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.SamlRequestData;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.springframework.core.io.Resource;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Specific IdP config for CAS itself.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class CasIdpConfig implements IIdpConfig {

	/** SVUID. */
	private static final long serialVersionUID = 1192077281021325726L;

	/** IdP config id. */
	private String id;

	/** IdP description. */
	private String description;

	/** IdP picture URL. */
	private String pictureUrl;

	/** Global Wayf Config. */
	private IWayfConfig wayfConfig;

	@Override
	public ISaml20IdpConnector getSaml20IdpConnector() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public SamlRequestData getSamlAuthnRequest(final SamlBindingEnum binding) {
		SamlRequestData fakeRequest = new SamlRequestData(null, null);

		RequestAttributes reqAttrs = RequestContextHolder.getRequestAttributes();
		if (reqAttrs instanceof ServletRequestAttributes) {
			ServletRequestAttributes servReqAttrs = (ServletRequestAttributes) reqAttrs;
			String flowExecutionKey = servReqAttrs.getRequest().getParameter("execution");
			fakeRequest.setEndpointUrl(String.format("/cas/login?_eventId=casIdp&execution=%s", flowExecutionKey));
		} else {
			// TODO MBD: what to do ?
		}

		return fakeRequest;
	}

	@Override
	public SamlRequestData getSamlSingleLogoutRequest(final SamlBindingEnum binding) {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public String getId() {
		return this.id;
	}

	public void setId(final String id) {
		this.id = id;
	}

	@Override
	public String getDescription() {
		return this.description;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

	@Override
	public String getPictureUrl() {
		return this.pictureUrl;
	}

	public void setPictureUrl(final String pictureUrl) {
		this.pictureUrl = pictureUrl;
	}

	@Override
	public IWayfConfig getWayfConfig() {
		return this.wayfConfig;
	}

	@Override
	public void registerWayfConfig(final IWayfConfig wayfConfig) {
		this.wayfConfig = wayfConfig;
	}

	@Override
	public String getIdpEntityId() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public long getTimeValidityWindow() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public SamlBindingEnum getRequestBinding() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public boolean isForceAuthentication() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public Resource getIdpMetadata() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public SamlBindingEnum getResponseBinding() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public Integer getAttributeConsumingServiceIndex() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public SignatureTrustEngine getSignatureTrustEngine() {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public String getIdpSsoEndpointUrl(final SamlBindingEnum binding) {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public String getIdpSloEndpointUrl(final SamlBindingEnum binding) {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

	@Override
	public void registerSaml20IdpConnector(final ISaml20IdpConnector saml20IdpConnector) {
		// Never used for CAS  IdP config !
		throw new IllegalAccessError("This method must not be called !");
	}

}
