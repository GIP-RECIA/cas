/*
 * Copyright 2007 The JA-SIG Collaborative. All rights reserved. See license
 * distributed with this file and available online at
 * http://www.ja-sig.org/products/cas/overview/license/
 */
package org.jasig.cas.web.view;

import java.util.ArrayList;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotNull;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.sso.security.saml.opensaml.OpenSamlCompatibilityHelper;
import org.esco.sso.security.saml.opensaml.OpenSamlHelper;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.principal.SamlService;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.validation.Assertion;
import org.opensaml.common.SAMLException;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.xml.io.MarshallingException;
import org.springframework.util.StringUtils;

/**
 * Implementation of a view to return a SAML response and assertion, based on
 * the SAML 1.1 specification.
 * <p>
 * If an AttributePrincipal is supplied, then the assertion will include the
 * attributes from it (assuming a String key/Object value pair). The only
 * Authentication attribute it will look at is the authMethod (if supplied).
 * <p>
 * Note that this class will currently not handle proxy authentication.
 * <p>
 * Note: This class currently expects a bean called "ServiceRegistry" to exist.
 * 
 * Modification GIP - RECIA 2012 : Adaptation to use opensaml 2 library.
 * 
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.1
 */
public class OldSaml10SuccessResponseView extends AbstractCasView {

	private static final Log LOGGER = LogFactory.getLog(OldSaml10SuccessResponseView.class);

	private static final String DEFAULT_ENCODING = "UTF-8";

	private static final String REMEMBER_ME_ATTRIBUTE_NAME = "longTermAuthenticationRequestTokenUsed";

	private static final String MODEL_PRINCIPAL_ID = "principalToUse";

	public static final String FILTER_ATTRIBUTE = "filterAttribute";

	/** The issuer, generally the hostname. */
	@NotNull
	private String issuer;

	/** The amount of time in milliseconds this is valid for. */
	private long issueLength = 30000;

	@NotNull
	private String encoding = OldSaml10SuccessResponseView.DEFAULT_ENCODING;

	@NotNull
	private String rememberMeAttributeName = OldSaml10SuccessResponseView.REMEMBER_ME_ATTRIBUTE_NAME;

	@Override
	protected void renderMergedOutputModel(final Map<String, Object> model, final HttpServletRequest request,
			final HttpServletResponse response) throws Exception {
		try {
			final Assertion assertion = this.getAssertionFrom(model);
			final Authentication authentication = assertion.getChainedAuthentications().get(0);
			final String principalId = (String) model.get(MODEL_PRINCIPAL_ID);
			final String principalFiltered = (String) model.get(FILTER_ATTRIBUTE);

			String xmlResponse = this.buildSaml10SuccessResponse(assertion, authentication, principalId, principalFiltered);

			if (StringUtils.hasText(xmlResponse)) {

				// Remove xml declaration header.
				xmlResponse = xmlResponse.substring(xmlResponse.indexOf(">") + 1);

				StringBuffer buffer = new StringBuffer(1024);
				buffer.append("<?xml version=\"1.0\" encoding=\"" + this.encoding + "\"?>");
				buffer.append("<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"><SOAP-ENV:Header/><SOAP-ENV:Body>");
				buffer.append(xmlResponse);
				buffer.append("</SOAP-ENV:Body></SOAP-ENV:Envelope>");

				response.setContentType("text/xml; charset=" + this.encoding);
				response.getWriter().print(buffer.toString());
				response.flushBuffer();

				OldSaml10SuccessResponseView.LOGGER.debug(String.format(
						"Success SOAP Envelope: [%s]", buffer.toString()));

			} else {
				OldSaml10SuccessResponseView.LOGGER.error("No SAML 1.1 Response built !");
			}

		} catch (final Exception e) {
			OldSaml10SuccessResponseView.LOGGER.error(e.getMessage(), e);
			throw e;
		}
	}

	protected String buildSaml10SuccessResponse(final Assertion assertion,
			final Authentication authentication, final String principalId, final String filteredAttribute) throws MarshallingException, SAMLException {
		String xmlResponse = null;

		final Service service = assertion.getService();
		if (service != null) {
			final String serviceId = service.getId();
			OldSaml10SuccessResponseView.LOGGER.debug(String.format(
					"Processing Successfull SAML 1.1 Request for service [%s] ...", serviceId));

			Response samlResponse = OpenSamlCompatibilityHelper.buildSamlResponse(
					serviceId, new ArrayList<org.opensaml.saml1.core.Assertion>(), null);

			if (SamlService.class.isAssignableFrom(service.getClass())) {
				final SamlService samlService = (SamlService) service;
				final String requestId = samlService.getRequestID();
				if (StringUtils.hasText(requestId)) {
					samlResponse.setInResponseTo(requestId);
				}
			}

			final org.opensaml.saml1.core.Assertion samlAssertion =
					OpenSamlCompatibilityHelper.buildAssertion(authentication,
							service, assertion, this.issuer, this.issueLength, this.rememberMeAttributeName, principalId, filteredAttribute);
			samlResponse.getAssertions().add(samlAssertion);

			Status status = OpenSamlCompatibilityHelper.buildStatus(OpenSamlCompatibilityHelper.STATUS_CODE_SUCCESS, null);
			samlResponse.setStatus(status);

			xmlResponse = OpenSamlHelper.marshallXmlObject(samlResponse);

			OldSaml10SuccessResponseView.LOGGER.debug(String.format(
					"Success SAML 1.1 Response built for service [%s] : [%s]", service.getId(), xmlResponse));
		}

		return xmlResponse;
	}

	public void setIssueLength(final long issueLength) {
		this.issueLength = issueLength;
	}

	public void setIssuer(final String issuer) {
		this.issuer = issuer;
	}

	public void setEncoding(final String encoding) {
		this.encoding = encoding;
	}

	public void setRememberMeAttributeName(final String rememberMeAttributeName) {
		this.rememberMeAttributeName = rememberMeAttributeName;
	}
}
