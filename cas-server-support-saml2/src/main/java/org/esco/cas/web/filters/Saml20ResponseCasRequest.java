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
import org.esco.cas.web.flow.Saml20EmailAuthenticationAction;
import org.esco.sso.security.saml.ISaml20SpProcessor;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.SamlHelper;
import org.esco.sso.security.saml.SamlProcessingException;
import org.esco.sso.security.saml.SamlRequestData;
import org.esco.sso.security.saml.SamlResponseData;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

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
	private SamlResponseData samlResponseData;

	@SuppressWarnings("unchecked")
	protected Saml20ResponseCasRequest(final HttpServletRequest request) throws SamlProcessingException {
		super(request);

		// Unlock the map
		this.parameters = new HashMap<String, String[]>(super.getParameterMap());

		Assert.isTrue(SamlHelper.isSamlResponse(request), "The request doesn't embed a SAML 2.0 Request !");

		// Process SAML response
		this.samlResponseData = this.processSaml2Request();

		if (this.samlResponseData != null) {
			// Retrieve initial params
			SamlRequestData initialRequest = this.samlResponseData.getOriginalRequestData();
			Assert.notNull(initialRequest, "No initial request corresponding to SAML response found !");

			Map<String, String[]> initialParams = initialRequest.getParametersMap();
			if (!CollectionUtils.isEmpty(initialParams)) {
				this.parameters.putAll(initialParams);
			}

			String idpIdParamKey = SamlHelper.getWayfConfig().getIdpIdParamKey();
			this.parameters.remove(idpIdParamKey);
			this.parameters.remove(SamlHelper.SAML_RESPONSE_PARAM_KEY);
			// Lock the map.
			this.parameters = MapUtils.unmodifiableMap(this.parameters);

			this.setAttribute(Saml20EmailAuthenticationAction.SAML_RESPONSE_DATA_FLOW_SCOPE_KEY,
					this.samlResponseData);
		}
	}

	protected SamlResponseData processSaml2Request() throws SamlProcessingException {
		SamlResponseData processedResponse = null;

		String servletPath = this.getServletPath();
		Saml20ResponseCasRequest.LOGGER.debug(String.format("SAML incoming request on servlet path: [%s]", servletPath));

		String samlService = null;
		String samlBinding = null;

		if (StringUtils.hasText(servletPath) &&
				servletPath.startsWith(SamlHelper.SAML2_SERVPATH_ROUTER)) {
			String[] routingArgs = servletPath.split("/");

			if ((routingArgs != null) && (routingArgs.length == 4)) {
				samlService = routingArgs[2];
				samlBinding = routingArgs[3];
			}
		}

		SamlBindingEnum binding = null;

		// SAML request routing ...
		if (StringUtils.hasText(samlBinding)) {
			if (SamlHelper.HTTP_POST_BINDING_SERVPATH_ROUTER.equals(samlBinding)) {
				binding = SamlBindingEnum.SAML_20_HTTP_POST;
			} else if (SamlHelper.HTTP_REDIRECT_BINDING_SERVPATH_ROUTER.equals(samlBinding)) {
				binding = SamlBindingEnum.SAML_20_HTTP_REDIRECT;
			} else {
				Saml20ResponseCasRequest.LOGGER.error(String.format("Incoming SAML request with unsupported binding: [%s] !", samlBinding));
			}
			Saml20ResponseCasRequest.LOGGER.debug(String.format("SAML incoming request binding: [%s]", binding.name()));
		}

		final String endpointUrl = this.getRequestURL().toString();
		final ISaml20SpProcessor spProcessor = SamlHelper.findSpProcessorToUse(endpointUrl);

		if (binding != null) {
			if (SamlHelper.ACS_SERVPATH_ROUTER.equals(samlService)) {
				Saml20ResponseCasRequest.LOGGER.debug("SAML incoming request is destinated to Assertion Consuming Service.");
				processedResponse = spProcessor.processSaml20IncomingRequest(this, binding);
			} else if (SamlHelper.SLO_SERVPATH_ROUTER.equals(samlService)) {
				Saml20ResponseCasRequest.LOGGER.debug("SAML incoming request is destinated to Single Logout Service.");
				processedResponse = spProcessor.processSaml20IncomingSingleLogoutRequest(this, binding);
			} else {
				Saml20ResponseCasRequest.LOGGER.error(String.format("Incoming SAML request for unsupported service: [%s] !", samlService));
			}
		}

		if (processedResponse == null) {
			String incomingRequest = null;
			if (SamlHelper.isSamlRequest(this)) {
				incomingRequest = SamlHelper.getSamlRequest(this);
			} else if (SamlHelper.isSamlResponse(this)) {
				incomingRequest = SamlHelper.getSamlResponse(this);
			}
			Saml20ResponseCasRequest.LOGGER.error(String.format("Unable to process SAML incoming request: [%s] !",
					incomingRequest));
		}

		return processedResponse;
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
