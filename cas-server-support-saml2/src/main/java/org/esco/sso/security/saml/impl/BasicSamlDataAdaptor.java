/**
 * 
 */
package org.esco.sso.security.saml.impl;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map.Entry;

import org.esco.sso.security.saml.ISamlDataAdaptor;
import org.esco.sso.security.saml.om.IOutgoingSaml;
import org.esco.sso.security.saml.om.IResponse;
import org.esco.sso.security.saml.query.IQuery;
import org.esco.sso.security.saml.util.SamlHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;
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
	private static final Logger LOGGER = LoggerFactory.getLogger(BasicSamlDataAdaptor.class);

	/**
	 * Retrieve the HTTP param name which will represent the SAML message.
	 * 
	 * @param outgoingData
	 * @return the HTTP param name
	 */
	public static String getSamlMessageParamName(final IOutgoingSaml outgoingData) {
		String paramName = null;

		if (outgoingData != null) {
			IQuery query = outgoingData.getSamlQuery();

			if (IResponse.class.isAssignableFrom(query.getClass())) {
				// The message is a Response
				paramName = SamlHelper.SAML_RESPONSE_PARAM_KEY;
			} else {
				paramName = SamlHelper.SAML_REQUEST_PARAM_KEY;
			}
		}

		return paramName;
	}

	@Override
	public String buildHttpRedirectBindingUrl(final IOutgoingSaml outgoingData) {
		final String samlMessage = outgoingData.getSamlMessage();
		final String relayState = outgoingData.getRelayState();

		// Encoding
		final String encodedMessage;
		String encodedRelayState = null;
		try {
			Assert.hasText(samlMessage, "SAML message cannot be empty !");
			encodedMessage = SamlHelper.httpRedirectEncode(samlMessage);
			if (StringUtils.hasText(relayState)) {
				encodedRelayState = URLEncoder.encode(relayState, "UTF-8");
			}
		} catch (Exception e) {
			final String message = "Error while Redirect encoding SAML message !";
			BasicSamlDataAdaptor.LOGGER.error(message, e);
			throw new IllegalStateException(message, e);
		}

		StringBuffer redirectUrl = new StringBuffer(2048);
		redirectUrl.append(outgoingData.getEndpointUrl());
		if (StringUtils.hasText(encodedMessage) && StringUtils.hasText(encodedRelayState)) {
			redirectUrl.append("?");
			if (StringUtils.hasText(encodedRelayState)) {
				redirectUrl.append(SamlHelper.RELAY_STATE_PARAM_KEY);
				redirectUrl.append("=");
				redirectUrl.append(encodedRelayState);
				redirectUrl.append("&");
			}
			redirectUrl.append(BasicSamlDataAdaptor.getSamlMessageParamName(outgoingData));
			redirectUrl.append("=");
			redirectUrl.append(encodedMessage);
		}

		String urlEncodedRequest = null;
		try {
			urlEncodedRequest = URLEncoder.encode(redirectUrl.toString(), SamlHelper.CHAR_ENCODING);
		} catch (UnsupportedEncodingException e) {
			final String message = "Error while URL encoding SAML message !";
			BasicSamlDataAdaptor.LOGGER.error(message, e);
			throw new IllegalStateException(message, e);
		}

		BasicSamlDataAdaptor.LOGGER.debug(
				"Basic HTTP-Redirect URL built: [{}]", urlEncodedRequest);

		return urlEncodedRequest;
	}

	@Override
	public Collection<Entry<String, String>> buildHttpPostBindingParams(final IOutgoingSaml outgoingData) {
		Collection<Entry<String, String>> samlDataParams =
				new ArrayList<Entry<String, String>>();

		String relayState = outgoingData.getRelayState();
		if (StringUtils.hasText(relayState)) {
			Entry<String, String> entry = new SimpleEntry<String, String>(
					SamlHelper.RELAY_STATE_PARAM_KEY, relayState);
			samlDataParams.add(entry);
		}

		String samlMessage = outgoingData.getSamlMessage();

		// Encoding
		final String encodedMessage;
		try {
			encodedMessage = SamlHelper.httpPostEncode(samlMessage);
		} catch (Exception e) {
			BasicSamlDataAdaptor.LOGGER.error(
					"Error while Redirect encoding SAML message !", e);
			throw new IllegalStateException("Error while Redirect encoding SAML message !", e);
		}

		if (StringUtils.hasText(encodedMessage)) {
			Entry<String, String> entry = new SimpleEntry<String, String>(
					BasicSamlDataAdaptor.getSamlMessageParamName(outgoingData), encodedMessage);
			samlDataParams.add(entry);
		}

		BasicSamlDataAdaptor.LOGGER.debug(String.format(
				"Basic HTTP-POST params built: [%s]", samlDataParams.toString()));

		return samlDataParams;
	}

}
