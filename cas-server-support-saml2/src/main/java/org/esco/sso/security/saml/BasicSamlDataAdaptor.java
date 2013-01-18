/**
 * 
 */
package org.esco.sso.security.saml;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map.Entry;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.StringUtils;

/**
 * Basic SAML data adaptor.
 * The SAML request is embedded in HTTP request with following parameters :
 * <ul>
 * <li>SAMLRequest</li>
 * <li>RelayState</li>
 * </ul>
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class BasicSamlDataAdaptor implements ISamlDataAdaptor {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(BasicSamlDataAdaptor.class);

	@Override
	public String buildHttpRedirectRequest(final SamlRequestData samlRequestData) {
		String samlRequest = samlRequestData.getSamlRequest();
		String relayState = samlRequestData.getRelayState();
		try {
			relayState = URLEncoder.encode(relayState, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			BasicSamlDataAdaptor.LOGGER.error(
					"Error while URL encoding Relay State.", e);
		}

		StringBuffer redirectUrl = new StringBuffer(2048);
		redirectUrl.append(samlRequestData.getEndpointUrl());
		if (StringUtils.hasText(relayState) && StringUtils.hasText(samlRequest)) {
			redirectUrl.append("?");
			redirectUrl.append(SamlHelper.RELAY_STATE_PARAM_KEY);
			redirectUrl.append("=");
			redirectUrl.append(relayState);
			redirectUrl.append("&");
			redirectUrl.append(SamlHelper.SAML_REQUEST_PARAM_KEY);
			redirectUrl.append("=");
			redirectUrl.append(samlRequest);
		}

		BasicSamlDataAdaptor.LOGGER.debug(String.format(
				"Basic HTTP-Redirect URL built: [%s]", redirectUrl.toString()));

		return redirectUrl.toString();
	}

	@Override
	public Collection<Entry<String, String>> buildHttpPostParams(final SamlRequestData samlRequestData) {
		Collection<Entry<String, String>> samlDataParams =
				new ArrayList<Entry<String, String>>();

		String relayState = samlRequestData.getRelayState();
		if (StringUtils.hasText(relayState)) {
			Entry<String, String> entry = new SimpleEntry<String, String>(
					SamlHelper.RELAY_STATE_PARAM_KEY, relayState);
			samlDataParams.add(entry);
		}

		String samlRequest = samlRequestData.getSamlRequest();
		if (StringUtils.hasText(samlRequest)) {
			Entry<String, String> entry = new SimpleEntry<String, String>(
					SamlHelper.SAML_REQUEST_PARAM_KEY, samlRequest);
			samlDataParams.add(entry);
		}

		BasicSamlDataAdaptor.LOGGER.debug(String.format(
				"Basic HTTP-POST params built: [%s]", samlDataParams.toString()));

		return samlDataParams;
	}

}
