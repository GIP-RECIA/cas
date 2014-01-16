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
package org.esco.cas.web.filters;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.web.flow.Saml20AuthenticationAction;
import org.esco.sso.security.saml.ISaml20SpProcessor;
import org.esco.sso.security.saml.exception.SamlProcessingException;
import org.esco.sso.security.saml.exception.UnsupportedSamlOperation;
import org.esco.sso.security.saml.om.IIncomingSaml;
import org.esco.sso.security.saml.query.IQuery;
import org.esco.sso.security.saml.query.impl.QueryAuthnRequest;
import org.esco.sso.security.saml.query.impl.QueryAuthnResponse;
import org.esco.sso.security.saml.util.SamlHelper;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * HTTP Servlet Request Wrapper which process a SAML 2.0 response and retrieve
 * parameters of initial CAS Request.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class Saml20ResponseCasRequest extends HttpServletRequestWrapper {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(Saml20ResponseCasRequest.class);

	/** Extended parameters. */
	private Map<String, String[]> parameters;

	/** SAML Response data from response processing. */
	private IIncomingSaml samlIncomingMsg;

	@SuppressWarnings("unchecked")
	protected Saml20ResponseCasRequest(final HttpServletRequest request)
			throws SamlProcessingException, UnsupportedSamlOperation {
		super(request);

		// Unlock the map
		this.parameters = new HashMap<String, String[]>(super.getParameterMap());

		Assert.isTrue(SamlHelper.isSamlResponse(request), "The request doesn't embed a SAML 2.0 Request !");

		// Process SAML response
		this.samlIncomingMsg = this.processSaml2Request();

		if (this.samlIncomingMsg != null) {
			final IQuery samlQuery = this.samlIncomingMsg.getSamlQuery();
			Assert.notNull(samlQuery, "No SAML query found in IncomingSaml message !");

			if (QueryAuthnResponse.class.isAssignableFrom(samlQuery.getClass())) {
				// The incoming message is a SAML Authn Response
				final QueryAuthnResponse authnResp = (QueryAuthnResponse) samlQuery;
				final QueryAuthnRequest authnReq = authnResp.getOriginalRequest();
				Assert.notNull(authnReq, "No initial Authn Req request corresponding to SAML response found !");

				// Retrieve initial params
				final Map<String, String[]> initialParams = authnReq.getParametersMap();
				Assert.notNull(initialParams, "No initial params bound to the initial request !");

				if (!CollectionUtils.isEmpty(initialParams)) {
					this.parameters.putAll(initialParams);
				}
			}

			final String idpIdParamKey = SamlHelper.getWayfConfig().getIdpIdParamKey();
			this.parameters.remove(idpIdParamKey);
			this.parameters.remove(SamlHelper.SAML_RESPONSE_PARAM_KEY);
			// Lock the map.
			this.parameters = MapUtils.unmodifiableMap(this.parameters);

			this.setAttribute(Saml20AuthenticationAction.SAML_RESPONSE_DATA_FLOW_SCOPE_KEY,
					this.samlIncomingMsg);
		}
	}

	protected IIncomingSaml processSaml2Request()
			throws SamlProcessingException, UnsupportedSamlOperation {
		IIncomingSaml incomingSaml = null;

		final String endpointUrl = this.getRequestURL().toString();
		final ISaml20SpProcessor spProcessor = SamlHelper.findSpProcessorToUse(endpointUrl);

		incomingSaml = spProcessor.processSaml20IncomingRequest(this);

		if (incomingSaml == null) {
			String incomingRequest = null;
			if (SamlHelper.isSamlRequest(this)) {
				incomingRequest = SamlHelper.getSamlRequest(this);
			} else if (SamlHelper.isSamlResponse(this)) {
				incomingRequest = SamlHelper.getSamlResponse(this);
			}
			Saml20ResponseCasRequest.LOGGER.error(String.format("Unable to process SAML incoming request: [%s] !",
					incomingRequest));
		}

		return incomingSaml;
	}

	/**
	 * Extended parametters whose includes initial CAS request parameters.
	 * {@inheritDoc}
	 */
	@Override
	public String getParameter(final String paramName) {
		String result = null;

		String[] values = this.getParameterValues(paramName);
		if (!ArrayUtils.isEmpty(values)) {
			result = values[0];
		}

		return result;
	}

	/**
	 * Extended parametters whose includes initial CAS request parameters.
	 * {@inheritDoc}
	 */
	@Override
	public String[] getParameterValues(final String paramName) {
		return this.parameters.get(paramName);
	}

	/**
	 * Extended parametters whose includes initial CAS request parameters.
	 * {@inheritDoc}
	 */
	@Override
	public Map<?,?> getParameterMap() {
		return this.parameters;
	}

}
