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
import org.jasig.cas.authentication.principal.SamlService;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.authentication.principal.WebApplicationService;
import org.jasig.cas.web.support.SamlArgumentExtractor;
import org.opensaml.common.SAMLException;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.xml.io.MarshallingException;
import org.springframework.util.StringUtils;

/**
 * Represents a failed attempt at validating a ticket, responding via a SAML
 * assertion.
 * 
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.1
 */
public class OldSaml10FailureResponseView extends AbstractCasView {

	private static final String DEFAULT_ENCODING = "UTF-8";

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(OldSaml10FailureResponseView.class);

	private final SamlArgumentExtractor samlArgumentExtractor = new SamlArgumentExtractor();

	@NotNull
	private String encoding = OldSaml10FailureResponseView.DEFAULT_ENCODING;

	@Override
	protected void renderMergedOutputModel(final Map<String, Object> model,
			final HttpServletRequest request, final HttpServletResponse response)
					throws Exception {
		final WebApplicationService service = this.samlArgumentExtractor.extractService(request);
		final String errorMessage = (String) model.get("description");

		String xmlResponse = this.buildSaml10FailureResponse(service, errorMessage);

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

			OldSaml10FailureResponseView.LOGGER.debug(String.format(
					"Failure SOAP Envelope: [%s]", buffer.toString()));
		}
	}

	protected String buildSaml10FailureResponse(final Service service, final String errormessage)
			throws MarshallingException, SAMLException {
		String xmlResponse = null;
		final String serviceId = service != null ? service.getId() : "UNKNOWN";

		OldSaml10FailureResponseView.LOGGER.debug(String.format(
				"Processing Failed SAML 1.1 Request for service [%s] ...", serviceId));

		Response samlResponse = OpenSamlCompatibilityHelper.buildSamlResponse(
				serviceId, new ArrayList<org.opensaml.saml1.core.Assertion>(), null);

		if (SamlService.class.isAssignableFrom(service.getClass())) {
			final SamlService samlService = (SamlService) service;
			final String requestId = samlService.getRequestID();
			if (StringUtils.hasText(requestId)) {
				samlResponse.setInResponseTo(requestId);
			}
		}

		Status status = OpenSamlCompatibilityHelper.buildStatus(
				OpenSamlCompatibilityHelper.STATUS_CODE_REQUEST_DENIED, errormessage);
		samlResponse.setStatus(status);

		xmlResponse = OpenSamlHelper.marshallXmlObject(samlResponse);

		OldSaml10FailureResponseView.LOGGER.debug(String.format(
				"Failure SAML 1.1 Response built for service [%s] : [%s]", serviceId, xmlResponse));

		return xmlResponse;
	}

	public void setEncoding(final String encoding) {
		this.encoding = encoding;
	}
}
