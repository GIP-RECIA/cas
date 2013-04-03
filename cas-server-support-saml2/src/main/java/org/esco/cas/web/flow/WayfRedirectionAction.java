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

import java.util.Collection;
import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.IWayfConfig;
import org.esco.sso.security.impl.CasIdpConfig;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.exception.SamlBuildingException;
import org.esco.sso.security.saml.om.IOutgoingSaml;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.webflow.action.AbstractAction;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class WayfRedirectionAction extends AbstractAction implements InitializingBean {

	private static final Log LOGGER = LogFactory.getLog(WayfRedirectionAction.class);

	private static final String CAS_IDP_SELECTION_EVENT_ID = "casIdp";

	private static final String SAML_REDIRECT_EVENT_ID = "samlRedirect";

	private static final String SAML_POST_EVENT_ID = "samlPost";

	/** Wayf configuration. */
	private IWayfConfig wayfConfig;

	@Override
	protected Event doExecute(final RequestContext context) throws Exception {
		IIdpConfig idpConfig = null;
		Event event = null;



		String idpIdStr = context.getRequestParameters().get(
				this.wayfConfig.getIdpIdParamKey());

		try {
			if (StringUtils.hasText(idpIdStr)) {
				final String idpId = idpIdStr;
				idpConfig = this.wayfConfig.findIdpConfigById(idpId);
			}

			if (idpConfig != null) {
				if (idpConfig instanceof CasIdpConfig) {
					event = new Event(this, WayfRedirectionAction.CAS_IDP_SELECTION_EVENT_ID);
				} else if (SamlBindingEnum.SAML_20_HTTP_POST == idpConfig.getRequestBinding()) {
					event = this.buildHttpPostRequest(context, idpConfig);
				} else if (SamlBindingEnum.SAML_20_HTTP_REDIRECT == idpConfig.getRequestBinding()) {
					event = this.buildHttpRedirectRequest(context, idpConfig);
				}
			}
		} catch (Exception e) {
			WayfRedirectionAction.LOGGER.error("Error while resolving the IdP Config or building the SAML Request !", e);
			throw e;
		}

		if (event == null) {
			event = this.error();
		}

		return event;
	}

	/**
	 * Build the event containing the HTTP Post Request for IdP redirect.
	 * Basically the event redirect to a page wich send a form with POST method.
	 * 
	 * @param context the webflow request context
	 * @param idpConfig the IdP config
	 * @return the redirect event
	 * @throws SamlBuildingException
	 */
	protected Event buildHttpPostRequest(final RequestContext context, final IIdpConfig idpConfig)
			throws SamlBuildingException {
		IOutgoingSaml authnHttpPostRequest = idpConfig
				.getSamlAuthnRequest(SamlBindingEnum.SAML_20_HTTP_POST);

		context.getFlowScope().put("authnRequestData", authnHttpPostRequest);
		Collection<Entry<String, String>> params = authnHttpPostRequest.getHttpPostBindingParams();
		context.getFlowScope().put("paramEntries", params);

		Event event = this.result(WayfRedirectionAction.SAML_POST_EVENT_ID);
		return event;
	}

	/**
	 * Build the event containing the HTTP Redirect Request for IdP redirect.
	 * Basically the event redirect directly to the IdP (GET method).
	 * 
	 * @param context the webflow request context
	 * @param idpConfig the IdP config
	 * @return the redirect event
	 * @throws SamlBuildingException
	 */
	protected Event buildHttpRedirectRequest(final RequestContext context, final IIdpConfig idpConfig)
			throws SamlBuildingException {
		IOutgoingSaml authnHttpRedirectRequest = idpConfig
				.getSamlAuthnRequest(SamlBindingEnum.SAML_20_HTTP_REDIRECT);

		final String samlHttpRedirectRequest = authnHttpRedirectRequest.getHttpRedirectBindingUrl();
		context.getFlowScope().put("urlToRedirect", samlHttpRedirectRequest);
		Event event = this.result(WayfRedirectionAction.SAML_REDIRECT_EVENT_ID);
		return event;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.wayfConfig, "No wayf configuration injected !");
	}

	/**
	 * Wayf configuration.
	 * 
	 * @return Wayf configuration.
	 */
	public IWayfConfig getWayfConfig() {
		return this.wayfConfig;
	}

	/**
	 * Wayf configuration.
	 * @param wayfConfig Wayf configuration.
	 */
	public void setWayfConfig(final IWayfConfig wayfConfig) {
		this.wayfConfig = wayfConfig;
	}

}
