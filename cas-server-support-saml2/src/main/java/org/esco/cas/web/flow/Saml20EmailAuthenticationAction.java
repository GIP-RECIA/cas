/**
 * Copyright (C) 2012 RECIA http://www.recia.fr
 * @Author (C) 2012 Maxime Bossard <mxbossard@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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

				// If a SAML response was found, the user is already authenticated via SAML
				List<String> emailAttributeValues = authentication.getAttribute(this.emailAttributeFriendlyName);

				credentials = new EmailAddressesCredentials(emailAttributeValues);

				SamlAuthInfo authInfos = credentials.getAuthenticationInformations();
				String idpEntityId = authnResp.getOriginalRequest().getIdpConnectorBuilder()
						.getIdpConfig().getIdpEntityId();
				Assert.notNull(idpEntityId, "The IdP entity ID cannot be null here !");
				authInfos.setIdpEntityId(idpEntityId);
				authInfos.setIdpSubject(authentication.getSubjectId());
				authInfos.setSessionIndex(authentication.getSessionIndex());

				// Put email credentials in flow scope
				context.getFlowScope().put(Saml20EmailAuthenticationAction.SAML_CREDENTIALS_FLOW_SCOPE_KEY, credentials);
			}
		} catch (Exception e) {
			Saml20EmailAuthenticationAction.LOGGER.error("Unable to retrieve SAML response from context !", e);
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
		Object object = request.getAttribute(Saml20EmailAuthenticationAction.SAML_RESPONSE_DATA_FLOW_SCOPE_KEY);

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
