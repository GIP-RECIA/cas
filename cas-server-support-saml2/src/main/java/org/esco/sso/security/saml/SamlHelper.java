/**
 * 
 */
package org.esco.sso.security.saml;

import java.util.ArrayList;
import java.util.Collection;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.sso.security.IWayfConfig;
import org.jasig.cas.web.support.WebUtils;
import org.springframework.util.StringUtils;
import org.springframework.webflow.execution.RequestContext;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class SamlHelper {

	/** Logger. */
	@SuppressWarnings("unused")
	private static final Log LOGGER = LogFactory.getLog(SamlHelper.class);

	/** SAML Response HTTP Param name. */
	public static final String SAML_RESPONSE_PARAM_KEY = "SAMLResponse";

	/** SAML Request HTTP Param name. */
	public static final String SAML_REQUEST_PARAM_KEY = "SAMLRequest";

	/** SAML Relay State HTTP Param name. */
	public static final String RELAY_STATE_PARAM_KEY = "RelayState";

	/** HTTP Request servlet path part for the Single Logout Service endpoint. */
	public static final String SAML2_SERVPATH_ROUTER = "/Shibboleth.sso/";

	/** HTTP Request servlet path part for the Single Logout Service endpoint. */
	public static final String SLO_SERVPATH_ROUTER = "SLO";

	/** HTTP Request servlet path part for the Assertion Consuming Service endpoint. */
	public static final String ACS_SERVPATH_ROUTER = "SAML2";

	/** HTTP Request servlet path part for a HTTP-POST binding. */
	public static final String HTTP_POST_BINDING_SERVPATH_ROUTER = "POST";

	/** HTTP Request servlet path part for a HTTP-Redirect binding. */
	public static final String HTTP_REDIRECT_BINDING_SERVPATH_ROUTER = "Redirect";

	/** The SP processor for CAS. */
	private static Collection<ISaml20SpProcessor> spProcessors = new ArrayList<ISaml20SpProcessor>(8);

	/** The wayf config for CAS. */
	private static IWayfConfig wayfConfig;

	/**
	 * Retrieve the SP processor for CAS corresponding to the endpoint URL.
	 * 
	 * @return the SP processor
	 * @throws SamlProcessingException if no SP Processor found to use
	 */
	public static ISaml20SpProcessor findSpProcessorToUse(final String endpointUrl) throws SamlProcessingException {
		for (ISaml20SpProcessor spProcessor : SamlHelper.spProcessors) {
			for(SamlBindingEnum binding : SamlBindingEnum.values()) {
				String spEnpointUrl = spProcessor.getSpConfig().getEndpointUrl(binding);
				if ((spEnpointUrl != null) && spEnpointUrl.equals(endpointUrl)) {
					if (SamlHelper.LOGGER.isDebugEnabled()) {
						SamlHelper.LOGGER.debug(String.format("EndpointUrl [%1$s] corrsponding to SPProcessor [%2$s]",
								endpointUrl, spProcessor.getSpConfig().getId()));
					}
					return spProcessor;
				}
			}
		}

		throw new SamlProcessingException(String.format(
				"Endpoint URL: [%1$s] isn't matching any registered SP processor !", endpointUrl));
	}

	/**
	 * Retrieve the IdP Connector corresponding to the entity ID.
	 * 
	 * @return the SP processor
	 */
	public static ISaml20IdpConnector findIdpConnectorToUse(final String idpEntityId) throws SamlProcessingException {
		for (ISaml20SpProcessor spProcessor : SamlHelper.spProcessors) {
			ISaml20IdpConnector idpConnector = spProcessor.findSaml20IdpConnectorToUse(idpEntityId);
			if (idpConnector != null) {
				return idpConnector;
			}
		}

		throw new SamlProcessingException(String.format(
				"IdP entityID: [%1$s] isn't matching any registered IdP Connector !", idpEntityId));
	}

	/**
	 * Register the SP processor for CAS.
	 * @param spProc the SP processor
	 */
	public static void registerSpProcessor(final ISaml20SpProcessor spProc) {
		SamlHelper.spProcessors.add(spProc);
	}

	/**
	 * Retrieve the wayf config for CAS.
	 * 
	 * @return the wayf config
	 */
	public static IWayfConfig getWayfConfig() {
		return SamlHelper.wayfConfig;
	}

	/**
	 * Register the wayf config for CAS.
	 * 
	 * @param wayfConf the wayf config
	 */
	public static void registerWayfConfig(final IWayfConfig wayfConf) {
		SamlHelper.wayfConfig = wayfConf;
	}

	/**
	 * Test if the spring webflow request context contain a SAML request.
	 * 
	 * @param context spring weblow request context
	 * @return true if the context contain a SAML Request
	 */
	public static boolean isSamlRequest(final RequestContext context) {
		final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

		return SamlHelper.isSamlRequest(request);
	}

	/**
	 * Test if the http request contain a SAML request.
	 * 
	 * @param context spring weblow request context
	 * @return true if the request contain a SAML Request
	 */
	public static boolean isSamlRequest(final HttpServletRequest request) {
		final String samlRequest = SamlHelper.getSamlRequest(request);

		return StringUtils.hasText(samlRequest);
	}

	/**
	 * Retrieve a SAML request from spring webflow request context.
	 * 
	 * @param context the spring webflow request context
	 * @return the SAML request.
	 */
	public static String getSamlRequest(final RequestContext context) {
		final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

		return SamlHelper.getSamlRequest(request);
	}

	/**
	 * Retrieve a SAML request from http request.
	 * 
	 * @param context the http request
	 * @return the SAML request.
	 */
	public static String getSamlRequest(final HttpServletRequest request) {
		return request.getParameter(SamlHelper.SAML_REQUEST_PARAM_KEY);
	}

	/**
	 * Test if the spring webflow request context contain a SAML response.
	 * 
	 * @param context spring weblow request context
	 * @return true if the context contain a SAML Response
	 */
	public static boolean isSamlResponse(final RequestContext context) {
		final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

		return SamlHelper.isSamlResponse(request);
	}

	/**
	 * Test if the http request contain a SAML response.
	 * 
	 * @param context spring weblow request context
	 * @return true if the request contain a SAML Response
	 */
	public static boolean isSamlResponse(final HttpServletRequest request) {
		final String samlResponse = SamlHelper.getSamlResponse(request);

		return StringUtils.hasText(samlResponse);
	}

	/**
	 * Retrieve a SAML response from spring webflow request context.
	 * 
	 * @param context the spring webflow request context
	 * @return the SAML response.
	 */
	public static String getSamlResponse(final RequestContext context) {
		final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

		return SamlHelper.getSamlResponse(request);
	}

	/**
	 * Retrieve a SAML response from http request.
	 * 
	 * @param context the http request
	 * @return the SAML response.
	 */
	public static String getSamlResponse(final HttpServletRequest request) {
		return request.getParameter(SamlHelper.SAML_RESPONSE_PARAM_KEY);
	}

	/**
	 * Retrieve relay state from spring webflow request context.
	 * 
	 * @param context the spring webflow request context
	 * @return the relay state.
	 */
	public static String getRelayState(final RequestContext context) {
		final HttpServletRequest request = WebUtils.getHttpServletRequest(context);

		return SamlHelper.getRelayState(request);
	}

	/**
	 * Retrieve relay state from http request.
	 * 
	 * @param request the http request
	 * @return the relay state.
	 */
	public static String getRelayState(final HttpServletRequest request) {
		String relayState = null;
		if (request != null) {
			relayState = request.getParameter(SamlHelper.RELAY_STATE_PARAM_KEY);
		}
		return relayState;
	}

}
