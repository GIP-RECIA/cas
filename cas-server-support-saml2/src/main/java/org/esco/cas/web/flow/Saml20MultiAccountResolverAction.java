/**
 * 
 */
package org.esco.cas.web.flow;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.ISaml20Facade;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.esco.cas.impl.SamlAuthInfo;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.om.IAuthentication;
import org.esco.sso.security.saml.om.IIncomingSaml;
import org.esco.sso.security.saml.query.IQuery;
import org.esco.sso.security.saml.query.impl.QueryAuthnResponse;
import org.jasig.cas.authentication.principal.Credentials;
import org.jasig.cas.web.flow.AbstractNonInteractiveCredentialsAction;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.util.Assert;
import org.springframework.webflow.execution.RequestContext;

/**
 * Retrieve email address authentication credentials from SAML response.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 * @author BULL - David BREYTON.
 *
 */
public class Saml20AuthenticationAction extends AbstractNonInteractiveCredentialsAction {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(Saml20AuthenticationAction.class);

	/** Saml response data flow scope key. */
	public static final String SAML_RESPONSE_DATA_FLOW_SCOPE_KEY = "samlResponseData";

	/** Saml credentials flow scope key. */
	public static final String SAML_CREDENTIALS_FLOW_SCOPE_KEY = "samlCredentials";

	/** Saml2 Facade. */
	private ISaml20Facade saml2Facade;

	@Override
	protected Credentials constructCredentialsFromRequest(final RequestContext context) {		
		Credentials credentials = null;
		try {

			// Only SAML Authn Responses need to be processed here !
			final QueryAuthnResponse authnResp = this.extractAuthnResponseFromContext(context);
			if (authnResp != null) {
				// The is a valid SAML Authn Response in the context

				// List of authentications
				final List<IAuthentication> authentications = authnResp.getSamlAuthentications();
				Assert.isTrue(authentications.size() == 1,
						"SAML Authn Response must contain 1 and only 1 authentication !");
				
				// Unique authentication
				final IAuthentication authentication = authentications.iterator().next();


				final ISaml20IdpConnector isSaml20IdpConnector = authnResp.getOriginalRequest().getIdpConnectorBuilder();
				final String friendlyName = isSaml20IdpConnector.getIdpConfig().getFriendlyName();
				Assert.notNull(friendlyName, "The friendlyName cannot be null here : the OpenSaml20IdpConnector must have a friendlyName ! ");
								
				// If a SAML response was found, the user is already authenticated via SAML
				List<String> vectorAttributeValues = authentication.getAttribute(friendlyName);

				final Class<? extends ISaml20Credentials> boundCredentialsType = isSaml20IdpConnector.getCredentialsType();
				Assert.notNull(boundCredentialsType, "The credential type cannot be null here : the OpenSaml20IdpConnector must have a credential type bound ! ");
				
				final ISaml20Credentials saml20Credentials = boundCredentialsType.newInstance();
				saml20Credentials.setAttributeFriendlyName(friendlyName);
				saml20Credentials.setAttributeValues(vectorAttributeValues);
								
				final SamlAuthInfo authInfos = saml20Credentials.getAuthenticationInformations();
				String idpEntityId = authnResp.getOriginalRequest().getIdpConnectorBuilder()
						.getIdpConfig().getIdpEntityId();
				Assert.notNull(idpEntityId, "The IdP entity ID cannot be null here !");
				authInfos.setIdpEntityId(idpEntityId);
				authInfos.setIdpSubject(authentication.getSubjectId());
				authInfos.setSessionIndex(authentication.getSessionIndex());
				
				credentials = saml20Credentials;

				// Put identity vector credentials in flow scope
				context.getFlowScope().put(Saml20AuthenticationAction.SAML_CREDENTIALS_FLOW_SCOPE_KEY, credentials);
			}
		} catch (Exception e) {
			Saml20AuthenticationAction.LOGGER.error("Unable to retrieve SAML response from context !", e);
		}

		return credentials;
	}

	/**
	 * Extract the QueryAuthnResponse from context if there is one !
	 * 
	 * @param context
	 * @return the QueryAuthnResponse or null
	 */
	protected QueryAuthnResponse extractAuthnResponseFromContext(final RequestContext context) {
		QueryAuthnResponse authnResp = null;

		// Retrieve the context corresponding SAML response
		HttpServletRequest request = WebUtils.getHttpServletRequest(context);
		Object object = request.getAttribute(Saml20AuthenticationAction.SAML_RESPONSE_DATA_FLOW_SCOPE_KEY);

		// Only SAML Authn Responses need to be processed here !
		if ((object != null) && (object instanceof IIncomingSaml)) {
			final IIncomingSaml incomingSaml = (IIncomingSaml) object;
			final IQuery samlQuery = incomingSaml.getSamlQuery();

			if (samlQuery instanceof QueryAuthnResponse) {
				// Our incoming SAML message is an Authn Response
				authnResp = (QueryAuthnResponse) samlQuery;
			}
		}

		return authnResp;
	}

	/**
	 * After successful SAML authentication, register the credentials for later use.
	 */
	@Override
	protected void onSuccess(final RequestContext context, final Credentials credentials) {
		ISaml20Credentials samlCredentials = (ISaml20Credentials) credentials;
		String tgtId = WebUtils.getTicketGrantingTicketId(context);

		Assert.notNull(tgtId, "The TGT Id cannot be null here !");

		this.saml2Facade.storeAuthCredentialsInCache(tgtId , samlCredentials);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();

		//Assert.notNull(this.emailAttributeFriendlyName, "No email attribute friendly name provided !");
		Assert.notNull(this.saml2Facade, "SAML 2.0 Facade wasn't injected !");
	}

	public ISaml20Facade getSaml2Facade() {
		return this.saml2Facade;
	}

	public void setSaml2Facade(final ISaml20Facade saml2Facade) {
		this.saml2Facade = saml2Facade;
	}
}
