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
package org.esco.cas.web;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.esco.cas.ISaml20Facade;
import org.esco.cas.authentication.principal.ISaml20Credentials;
import org.esco.cas.impl.SamlAuthInfo;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.exception.SamlBuildingException;
import org.esco.sso.security.saml.om.IOutgoingSaml;
import org.esco.sso.security.saml.util.SamlHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.AbstractController;
import org.springframework.web.servlet.mvc.Controller;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Controller to perform a SAML 2.0 Logout with the CAS logout.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public final class SamlSingleLogoutController extends AbstractController implements InitializingBean {

	private static final Logger LOGGER = LoggerFactory.getLogger(SamlSingleLogoutController.class);

	/** The original CAS logout controller. */
	private Controller logoutController;

	/** CAS Ticket Registry. */
	private ISaml20Facade saml2Facade;

	/** Silent SLO : if true perform a silent SLO. */
	private boolean singleLogoutSilently = false;

	/** List of IdPs logout URL to emulate SLO. */
	private List<String> idpsLogoutUrlIframeCall;

	/** List of logout URL to call via iframes to emulate SLO. */
	private List<String> singleLogoutUrlIframeCall;

	@Override
	protected ModelAndView handleRequestInternal(
			final HttpServletRequest request, final HttpServletResponse response)
					throws Exception {
		// Standard logout
		ModelAndView mv = this.logoutController.handleRequest(request, response);

		// P3P header pour encapsulation de la page de logout dans des iframes
		response.addHeader("P3P", "CP=\"IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT\"");

		// SAML Single Logout
		String tgtId = this.saml2Facade.retrieveTgtIdFromCookie(request);

		if (StringUtils.hasText(tgtId)) {
			ISaml20Credentials authCreds = this.saml2Facade.retrieveAuthCredentialsFromCache(tgtId);
			SamlAuthInfo authInfos = null;
			
			// MBD FIX 2013-09-12 : SamlAuthInfo IdP entity Id may be null !
			if (authCreds != null && (authInfos = authCreds.getAuthenticationInformations()) != null && authInfos.getIdpEntityId() != null) {
				// The user authentified via SAML !
				ISaml20IdpConnector idpConnector = SamlHelper.findIdpConnectorToUse(
						authInfos.getIdpEntityId());

				String httpRedirectLogoutUrl = null;
				try {
					final IOutgoingSaml outgoingSaml = idpConnector.buildSaml20SingleLogoutRequest(
							request, SamlBindingEnum.SAML_20_HTTP_REDIRECT);

					httpRedirectLogoutUrl = outgoingSaml.getHttpRedirectBindingUrl();

					if (this.singleLogoutSilently) {
						// Send silent SLO from server
						this.silentLogout(idpConnector, outgoingSaml);
					} else {
						// Redirect browser with SLO
						mv = new ModelAndView(new RedirectView(httpRedirectLogoutUrl));
					}

				} catch (SamlBuildingException e) {
					// Error while building the SLO request.
					SamlSingleLogoutController.LOGGER.error("Error while building SAML 2.0 SLO Request !", e);
				} catch (IOException e) {
					// Error while building the SLO request.
					SamlSingleLogoutController.LOGGER.error("Error while sending SLO Request to URL: [{}] with error message: [{}] !",
							httpRedirectLogoutUrl, e.getMessage());
					SamlSingleLogoutController.LOGGER.debug("Error while sending SLO Request !", e);
				}

			}
		}

		mv.addObject("idpsLogoutUrl", this.getSingleLogoutUrl());

		return mv;
	}

	private void silentLogout(final ISaml20IdpConnector idpConnector,
			final IOutgoingSaml outgoingSaml) throws MalformedURLException, IOException {
		URL logoutUrl = new URL(outgoingSaml.getHttpRedirectBindingUrl());
		HttpURLConnection logoutConnection = (HttpURLConnection) logoutUrl.openConnection();
		logoutConnection.setReadTimeout(10000);
		logoutConnection.connect();

		InputStream responseStream = logoutConnection.getInputStream();

		StringWriter writer = new StringWriter();
		IOUtils.copy(responseStream, writer, "UTF-8");
		String response = writer.toString();

		SamlSingleLogoutController.LOGGER.debug("HTTP response to SLO Request which was send: [{}] ", response);

		int responseCode = logoutConnection.getResponseCode();

		String idpEntityId = idpConnector.getIdpConfig().getIdpEntityId();
		if (responseCode < 0) {
			SamlSingleLogoutController.LOGGER.warn("IdP response is not a valid HTTP Response !",
					outgoingSaml.getSamlMessage(), idpEntityId);
		} else if (responseCode == 200) {
			SamlSingleLogoutController.LOGGER.info("SAML 2.0 Single Logout Request correctly received by IdP [{}] !",
					idpEntityId);
		} else {
			SamlSingleLogoutController.LOGGER.warn(
					"HTTP response code: [{}] ! IdP rejected our SAML 2.0 Single Logout Request [{}] to IdP [{}] !",
					new Object[] {responseCode, outgoingSaml.getSamlMessage(), idpEntityId});
		}

		logoutConnection.disconnect();
	}

	/**
	 * Array representation of ordered list of all LDAP filters to try for authenticate an email Address.
	 * 
	 * @param authenticationLdapFilters the ordered filters
	 */
	public void setIdpsLogoutUrlIframeCall(final String[] idpsLogoutUrlIframeCall) {
		Assert.noNullElements(idpsLogoutUrlIframeCall, "Array is null !");

		List<String> list = new ArrayList<String>();
		CollectionUtils.mergeArrayIntoCollection(idpsLogoutUrlIframeCall, list);

		this.idpsLogoutUrlIframeCall = list;
	}


	/**
	 * Array representation of ordered list of all LDAP filters to try for authenticate an email Address.
	 * 
	 * @param authenticationLdapFilters the ordered filters
	 */
	public void setSingleLogoutUrlIframeCall(final String[] singleLogoutUrlIframeCall) {
		Assert.noNullElements(singleLogoutUrlIframeCall, "Array is null !");

		List<String> list = new ArrayList<String>();
		CollectionUtils.mergeArrayIntoCollection(singleLogoutUrlIframeCall, list);

		this.singleLogoutUrlIframeCall = list;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.logoutController, "The CAS logout controller wasn't injected !");
		Assert.notNull(this.saml2Facade, "SAML 2.0 Facade wasn't injected !");
	}

	public Controller getLogoutController() {
		return this.logoutController;
	}

	public void setLogoutController(final Controller logoutController) {
		this.logoutController = logoutController;
	}

	public ISaml20Facade getSaml2Facade() {
		return this.saml2Facade;
	}

	public void setSaml2Facade(final ISaml20Facade saml2Facade) {
		this.saml2Facade = saml2Facade;
	}

	/**
	 * Silent SLO : if true perform a silent SLO.
	 * 
	 * @param singleLogoutSilently the config
	 */
	public void setSingleLogoutSilently(final boolean singleLogoutSilently) {
		this.singleLogoutSilently = singleLogoutSilently;
	}

	public List<String> getIdpsLogoutUrl() {
		return this.idpsLogoutUrlIframeCall;
	}

	public List<String> getSingleLogoutUrl() {
		return this.singleLogoutUrlIframeCall;
	}

}
