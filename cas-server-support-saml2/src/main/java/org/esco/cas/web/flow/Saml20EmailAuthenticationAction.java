/**
 * 
 */
package org.esco.cas.web.flow;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.ISaml20Facade;
import org.esco.cas.authentication.principal.EmailAddressesCredentials;
import org.esco.cas.impl.SamlAuthInfo;
import org.esco.sso.security.saml.SamlResponseData;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.flow.AbstractNonInteractiveCredentialsAction;
import org.jasig.cas.web.support.WebUtils;
import org.opensaml.saml2.core.Subject;
import org.springframework.util.Assert;
import org.springframework.webflow.execution.RequestContext;

/**
 * Retrieve email address authentication credentials from SAML response.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class Saml20EmailAuthenticationAction extends AbstractNonInteractiveCredentialsAction {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(Saml20EmailAuthenticationAction.class);

	/** Saml response data flow scope key. */
	public static final String SAML_RESPONSE_DATA_FLOW_SCOPE_KEY = "samlResponseData";

	/** Saml credentials flow scope key. */
	public static final String SAML_CREDENTIALS_FLOW_SCOPE_KEY = "samlCredentials";

	/** Email attribute friendly name in SAML response. */
	private String emailAttributeFriendlyName;

	/** Saml2 Facade. */
	private ISaml20Facade saml2Facade;

	@Override
	protected Credentials constructCredentialsFromRequest(final RequestContext context) {
		EmailAddressesCredentials credentials = null;
		try {

			// Retrieve the context corresponding SAML response
			HttpServletRequest request = WebUtils.getHttpServletRequest(context);
			Object object = request.getAttribute(Saml20EmailAuthenticationAction.SAML_RESPONSE_DATA_FLOW_SCOPE_KEY);

			if ((object != null) && (object instanceof SamlResponseData)) {
				SamlResponseData responseData = (SamlResponseData) object;
				// If a SAML response was found, the user is already authenticated via SAML
				List<String> emailAttributeValues = responseData.getAttribute(this.emailAttributeFriendlyName);

				credentials = new EmailAddressesCredentials(emailAttributeValues);

				SamlAuthInfo authInfos = credentials.getAuthenticationInformations();
				String idpEntityId = responseData.getOriginalRequestData().getIdpConnectorBuilder()
						.getIdpConfig().getIdpEntityId();
				Assert.notNull(idpEntityId, "The IdP entity ID cannot be null here !");
				authInfos.setIdpEntityId(idpEntityId);
				Subject subject = responseData.getSamlSubject();
				authInfos.setIdpSubject(subject);
				authInfos.setSessionIndex(responseData.getSessionIndex());

				// Put email credentials in flow scope
				context.getFlowScope().put(Saml20EmailAuthenticationAction.SAML_CREDENTIALS_FLOW_SCOPE_KEY, credentials);
			}
		} catch (Exception e) {
			Saml20EmailAuthenticationAction.LOGGER.error("Unable to retrieve SAML response from context !", e);
		}

		return credentials;
	}

	/**
	 * After successful SAML authentication, register the credentials for later use.
	 */
	@Override
	protected void onSuccess(final RequestContext context, final Credentials credentials) {
		EmailAddressesCredentials emailCredentials = (EmailAddressesCredentials) credentials;
		String tgtId = WebUtils.getTicketGrantingTicketId(context);

		Assert.notNull(tgtId, "The TGT Id cannot be null here !");

		this.saml2Facade.storeAuthenticationInfosInCache(tgtId , emailCredentials.getAuthenticationInformations());
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();

		Assert.notNull(this.emailAttributeFriendlyName, "No email attribute friendly name provided !");
		Assert.notNull(this.saml2Facade, "SAML 2.0 Facade wasn't injected !");
	}

	/**
	 * Email attribute friendly name in SAML response.
	 * 
	 * @return the friendly name
	 */
	public String getEmailAttributeFriendlyName() {
		return this.emailAttributeFriendlyName;
	}

	/**
	 * Email attribute friendly name in SAML response.
	 * 
	 * @param emailAttributeFriendlyName the friendly name
	 */
	public void setEmailAttributeFriendlyName(final String emailAttributeFriendlyName) {
		this.emailAttributeFriendlyName = emailAttributeFriendlyName;
	}

	public ISaml20Facade getSaml2Facade() {
		return this.saml2Facade;
	}

	public void setSaml2Facade(final ISaml20Facade saml2Facade) {
		this.saml2Facade = saml2Facade;
	}


}
