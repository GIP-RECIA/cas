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
import org.esco.sso.security.saml.impl.BasicSamlDataAdaptor;
import org.esco.sso.security.saml.om.IOutgoingSaml;
import org.esco.sso.security.saml.util.SamlHelper;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.StringUtils;

/**
 * CATEL specific SAML data adaptor.
 * The basic SAML request params are embbeded in one HTTP parameter.
 *
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class CatelSamlDataAdaptor implements ISamlDataAdaptor, InitializingBean {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(CatelSamlDataAdaptor.class);

	/** CATEL specific IdP enpoint URL. */
	private static final String CATEL_ENDPOINT_URL =
			"https://extranet.ac-orleans-tours.fr/login/ct_logon_mixte.jsp";

	/** CATEL specific HTTP param name for SAML requests. */
	private static final String HTTP_PARAM_NAME = "CT_ORIG_URL";

	/** CATEL specific original IdP endpoint. */
	private static final String ORIGINAL_SSO_ENPOINT = "/sso/SSO";

	/** If set override de default catel endpoint URL. */
	private String catelEndpointUrl;

	public CatelSamlDataAdaptor() {
		super();
	}

	@Override
	public String buildHttpRedirectBindingUrl(final IOutgoingSaml outgoingData) {
		String redirectBindingUrl = null;

		if (outgoingData != null) {
			final String samlMessage = outgoingData.getSamlMessage();
			final String relayState = outgoingData.getRelayState();

			// Encoding
			final String encodedMessage;
			try {
				encodedMessage = SamlHelper.httpRedirectEncode(samlMessage);
			} catch (Exception e) {
				CatelSamlDataAdaptor.LOGGER.error(
						"Error while Redirect encoding SAML message !", e);
				throw new IllegalStateException("Error while Redirect encoding SAML message !", e);
			}

			final StringBuffer redirectUrl = new StringBuffer(2048);
			redirectUrl.append(this.catelEndpointUrl
					+ "?" + CatelSamlDataAdaptor.HTTP_PARAM_NAME + "=");
			try {
				final String urlEncodedMessage = URLEncoder.encode(encodedMessage, "UTF-8");
				final String urlEncodedRelayState = URLEncoder.encode(relayState, "UTF-8");

				final StringBuffer catelSpecific = new StringBuffer(2048);
				if (StringUtils.hasText(urlEncodedMessage)) {
					catelSpecific.append(CatelSamlDataAdaptor.ORIGINAL_SSO_ENPOINT);
					catelSpecific.append("?");
					if (StringUtils.hasText(urlEncodedRelayState)) {
						catelSpecific.append(SamlHelper.RELAY_STATE_PARAM_KEY);
						catelSpecific.append("=");
						catelSpecific.append(urlEncodedRelayState);
						catelSpecific.append("&");
					}
					catelSpecific.append(BasicSamlDataAdaptor.getSamlMessageParamName(outgoingData));
					catelSpecific.append("=");
					catelSpecific.append(urlEncodedMessage);
				}

				String catelSpecificUrlEncoded = URLEncoder.encode(catelSpecific.toString(), "UTF-8");
				redirectUrl.append(catelSpecificUrlEncoded);
			} catch (UnsupportedEncodingException e) {
				final String message = "Error while URL encoding CATEL specific Redirect URL !";
				CatelSamlDataAdaptor.LOGGER.error(message, e);
				throw new IllegalStateException(message, e);
			}

			redirectBindingUrl = redirectUrl.toString();

			CatelSamlDataAdaptor.LOGGER.debug(String.format(
					"CATEL specific HTTP-Redirect URL built: [%s]", redirectUrl.toString()));
		}

		return redirectBindingUrl;
	}

	@Override
	public Collection<Entry<String, String>> buildHttpPostBindingParams(final IOutgoingSaml outgoingData) {
		Collection<Entry<String, String>> samlDataParams = new ArrayList<Entry<String, String>>();

		final StringBuffer catelSpecific = new StringBuffer(2048);
		final String relayState = outgoingData.getRelayState();
		final String samlMessage = outgoingData.getSamlMessage();

		// Encoding
		final String encodedMessage;
		try {
			encodedMessage = SamlHelper.httpPostEncode(samlMessage);
		} catch (Exception e) {
			CatelSamlDataAdaptor.LOGGER.error(
					"Error while Redirect encoding SAML message !", e);
			throw new IllegalStateException("Error while Redirect encoding SAML message !", e);
		}

		if (StringUtils.hasText(encodedMessage)) {
			catelSpecific.append(CatelSamlDataAdaptor.ORIGINAL_SSO_ENPOINT);
			catelSpecific.append("?");
			if (StringUtils.hasText(relayState)) {
				catelSpecific.append(SamlHelper.RELAY_STATE_PARAM_KEY);
				catelSpecific.append("=");
				catelSpecific.append(relayState);
				catelSpecific.append("&");
			}
			catelSpecific.append(BasicSamlDataAdaptor.getSamlMessageParamName(outgoingData));
			catelSpecific.append("=");
			catelSpecific.append(encodedMessage);

			try {
				String catelSpecificEncoded = URLEncoder.encode(catelSpecific.toString(), "UTF-8");
				Entry<String, String> entry = new SimpleEntry<String, String>(
						CatelSamlDataAdaptor.HTTP_PARAM_NAME, catelSpecificEncoded);
				samlDataParams.add(entry);
			} catch (UnsupportedEncodingException e) {
				final String message = "Error while URL encoding CATEL specific Redirect URL !";
				CatelSamlDataAdaptor.LOGGER.error(message, e);
				throw new IllegalStateException(message, e);
			}
		}

		CatelSamlDataAdaptor.LOGGER.debug(String.format(
				"CATEL specific HTTP-POST params built: [%s]", samlDataParams.toString()));

		return samlDataParams;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		if (!StringUtils.hasText(this.catelEndpointUrl)) {
			this.catelEndpointUrl = CatelSamlDataAdaptor.CATEL_ENDPOINT_URL;
		}
	}

	public void setCatelEndpointUrl(final String catelEndpointUrl) {
		this.catelEndpointUrl = catelEndpointUrl;
	}

}
