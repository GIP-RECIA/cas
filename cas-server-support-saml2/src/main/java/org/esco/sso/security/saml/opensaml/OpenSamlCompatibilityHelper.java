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
package org.esco.sso.security.saml.opensaml;

import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Map.Entry;

import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.authentication.Authentication;
import org.jasig.cas.authentication.SamlAuthenticationMetaDataPopulator;
import org.jasig.cas.authentication.principal.RememberMeCredentials;
import org.jasig.cas.authentication.principal.Service;
import org.jasig.cas.validation.Assertion;
import org.joda.time.DateTime;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.AttributeStatement;
import org.opensaml.saml1.core.AttributeValue;
import org.opensaml.saml1.core.Audience;
import org.opensaml.saml1.core.AudienceRestrictionCondition;
import org.opensaml.saml1.core.AuthenticationStatement;
import org.opensaml.saml1.core.Conditions;
import org.opensaml.saml1.core.ConfirmationMethod;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml1.core.Response;
import org.opensaml.saml1.core.Status;
import org.opensaml.saml1.core.StatusCode;
import org.opensaml.saml1.core.StatusMessage;
import org.opensaml.saml1.core.Subject;
import org.opensaml.saml1.core.SubjectConfirmation;
import org.opensaml.saml1.core.impl.ResponseBuilder;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.Namespace;
import org.opensaml.xml.NamespaceManager;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.impl.XSAnyBuilder;
import org.springframework.util.StringUtils;

/**
 * Helper for backward compatibility between opensaml 1.1 and opensaml 2.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public abstract class OpenSamlCompatibilityHelper {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(OpenSamlCompatibilityHelper.class);

	/** SAML 1.1 Response builder. */
	private static final ResponseBuilder responseBuilder = new ResponseBuilder();

	/** SAML 1.1 prefix. */
	public static final String SAML_PREFIX = "saml";

	/** SAML 1.1 protocol prefix. */
	public static final String SAMLP_PREFIX = "samlp";

	/** SAML 1.1 SUCCESS Status Code. */
	public static QName STATUS_CODE_SUCCESS = new QName(SAMLConstants.SAML10P_NS, "Success", OpenSamlCompatibilityHelper.SAMLP_PREFIX);

	/** SAML 1.1 REQUEST_DENIED Status Code. */
	public static final QName STATUS_CODE_REQUEST_DENIED = new QName(SAMLConstants.SAML10P_NS, "RequestDenied",
			OpenSamlCompatibilityHelper.SAMLP_PREFIX);

	/** SAML 1.1 Authentication Method unspecified. */
	public static final String AUTHN_METHOD_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.0:am:unspecified";

	/** Namespace for custom attributes. */
	private static final String CAS_NAMESPACE = "http://www.ja-sig.org/products/cas/";

	/** Artifact Conf Method URI. */
	private static final String ARTIFACT_CONF_METHOD_URI = "urn:oasis:names:tc:SAML:1.0:cm:artifact";

	/** Id generator. */
	private static IdentifierGenerator idGenerator;

	static {
		try {
			OpenSamlCompatibilityHelper.idGenerator = new SecureRandomIdentifierGenerator();
		} catch (NoSuchAlgorithmException e) {
			OpenSamlCompatibilityHelper.LOGGER.error("Unable to generate random hex string !", e);
		}
	}

	/** SAML 1.1 XS Any builder. */
	private static final XSAnyBuilder xsAnyBuilder = new XSAnyBuilder();

	/** Remember me attribute value. */
	private static final String REMEMBER_ME_ATTRIBUTE_VALUE = "true";

	/**
	 * Build a SAML 1.1 Response like the opensaml 1.1 library.
	 * 
	 * @param recipient
	 * @param assertions
	 * @param e
	 * @param assertions
	 * @return a SAML 1.1 Response
	 */
	public static Response buildSamlResponse(final String recipient,
			final Collection<org.opensaml.saml1.core.Assertion> assertions, final SAMLException e) {
		final Response samlResponse = OpenSamlCompatibilityHelper.responseBuilder
				.buildObject(SAMLConstants.SAML10P_NS, Response.DEFAULT_ELEMENT_LOCAL_NAME, null);

		Namespace samlNs = new Namespace(SAMLConstants.SAML1_NS, "saml");
		Namespace samlpNs = new Namespace(SAMLConstants.SAML10P_NS, "samlp");

		Namespace xsdNs = new Namespace("http://www.w3.org/2001/XMLSchema", "xsd");
		Namespace xsipNs = new Namespace("http://www.w3.org/2001/XMLSchema-instance", "xsi");

		NamespaceManager nsManager = samlResponse.getNamespaceManager();
		nsManager.registerNamespace(samlNs);
		nsManager.registerNamespace(samlpNs);
		nsManager.registerNamespace(xsdNs);
		nsManager.registerNamespace(xsipNs);

		String id = OpenSamlCompatibilityHelper.idGenerator.generateIdentifier();
		DateTime issueInstant = new DateTime();

		samlResponse.setID(id);
		samlResponse.setIssueInstant(issueInstant);
		samlResponse.setRecipient(recipient);
		samlResponse.getAssertions().addAll(assertions);
		samlResponse.setVersion(SAMLVersion.VERSION_11);

		return samlResponse;
	}

	/**
	 * Build the SAML 1.1 Assertion with attributes.
	 * 
	 * @param authentication the CAS authentication
	 * @param service the CAS service in use
	 * @param assertion the CAS Assertion
	 * @param issuer
	 * @param issueLength
	 * @param rememberMeAttributeName
	 * @return the SAML 1.1 Assertion
	 * @throws SAMLException
	 */
	public static org.opensaml.saml1.core.Assertion buildAssertion(final Authentication authentication,
			final Service service, final Assertion assertion, final String issuer,
			final long issueLength, final String rememberMeAttributeName, final String principalId, final String filteredAttribute)
					throws SAMLException {

		final DateTime currentDate = new DateTime();
		final String authenticationMethod = (String) authentication.getAttributes()
				.get(SamlAuthenticationMetaDataPopulator.ATTRIBUTE_AUTHENTICATION_METHOD);
		final boolean isRemembered = ((authentication.getAttributes()
				.get(RememberMeCredentials.AUTHENTICATION_ATTRIBUTE_REMEMBER_ME) == Boolean.TRUE)
				&& !assertion.isFromNewLogin());

		XMLObjectBuilderFactory builder = Configuration.getBuilderFactory();

		final org.opensaml.saml1.core.Assertion samlAssertion = (org.opensaml.saml1.core.Assertion)
				builder.getBuilder(org.opensaml.saml1.core.Assertion.DEFAULT_ELEMENT_NAME)
				.buildObject(SAMLConstants.SAML1_NS,
						org.opensaml.saml1.core.Assertion.DEFAULT_ELEMENT_LOCAL_NAME, null);

		String id = OpenSamlCompatibilityHelper.idGenerator.generateIdentifier();
		samlAssertion.setID(id);

		samlAssertion.setIssueInstant(currentDate);
		samlAssertion.setIssuer(issuer);
		samlAssertion.setVersion(SAMLVersion.VERSION_11);

		// Conditions
		Conditions conditions = OpenSamlCompatibilityHelper.buildSamlObject(Conditions.DEFAULT_ELEMENT_NAME);
		samlAssertion.setConditions(conditions);
		conditions.setNotBefore(currentDate);
		conditions.setNotOnOrAfter(currentDate.plus(issueLength));

		// Audience
		AudienceRestrictionCondition samlAudienceRestrictionCondition =
				OpenSamlCompatibilityHelper.buildSamlObject(AudienceRestrictionCondition.DEFAULT_ELEMENT_NAME);
		Audience audience = OpenSamlCompatibilityHelper.buildSamlObject(Audience.DEFAULT_ELEMENT_NAME);

		audience.setUri(service.getId());
		samlAudienceRestrictionCondition.getAudiences().add(audience);
		conditions.getAudienceRestrictionConditions().add(samlAudienceRestrictionCondition);

		// Attribute Statement
		if (!authentication.getPrincipal().getAttributes().isEmpty() || isRemembered) {
			final AttributeStatement attributeStatement =
					OpenSamlCompatibilityHelper.buildSamlObject(AttributeStatement.DEFAULT_ELEMENT_NAME);

			attributeStatement.setSubject(OpenSamlCompatibilityHelper.buildNewSamlSubject(principalId));
			samlAssertion.getStatements().add(attributeStatement);

			for (final Entry<String, Object> e : authentication.getPrincipal().getAttributes().entrySet()) {
				Attribute attribute = OpenSamlCompatibilityHelper.buildAttribute(e.getKey(),
						OpenSamlCompatibilityHelper.CAS_NAMESPACE, e.getValue());
				if (attribute != null && !e.getKey().equalsIgnoreCase(filteredAttribute)) {
					attributeStatement.getAttributes().add(attribute);
				}
			}

			if (isRemembered) {
				final Attribute attribute = OpenSamlCompatibilityHelper.buildAttribute(rememberMeAttributeName,
						OpenSamlCompatibilityHelper.CAS_NAMESPACE, OpenSamlCompatibilityHelper.REMEMBER_ME_ATTRIBUTE_VALUE);
				attributeStatement.getAttributes().add(attribute);
			}
		}


		// Authentication Statement
		AuthenticationStatement authStatement =
				OpenSamlCompatibilityHelper.buildSamlObject(AuthenticationStatement.DEFAULT_ELEMENT_NAME);

		samlAssertion.getAuthenticationStatements().add(authStatement);
		DateTime authInstant = new DateTime(authentication.getAuthenticatedDate().getTime());
		authStatement.setAuthenticationInstant(authInstant);

		if (StringUtils.hasText(authenticationMethod)) {
			authStatement.setAuthenticationMethod(authenticationMethod);
		} else {
			authStatement.setAuthenticationMethod(OpenSamlCompatibilityHelper.AUTHN_METHOD_UNSPECIFIED);
		}
		// Subject
		authStatement.setSubject(OpenSamlCompatibilityHelper.buildNewSamlSubject(principalId));

		return samlAssertion;
	}

	public static Attribute buildAttribute(final String name, final String namespace, final Object values) {
		final Attribute attribute =
				OpenSamlCompatibilityHelper.buildSamlObject(Attribute.DEFAULT_ELEMENT_NAME);

		attribute.setAttributeName(name);
		attribute.setAttributeNamespace(namespace);

		if ((values != null) && (values instanceof Collection<?>)) {
			final Collection<?> valuesCollection = (Collection<?>) values;
			if (valuesCollection.isEmpty()) {
				// 100323 bnoordhuis: don't add the attribute, it causes a org.opensaml.MalformedException
				return null;
			}
			for (Object value : valuesCollection) {
				if (value != null) {
					XSAny container = OpenSamlCompatibilityHelper.xsAnyBuilder
							.buildObject(SAMLConstants.SAML1_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, null);

					container.setTextContent(value.toString());
					attribute.getAttributeValues().add(container);
				}
			}
		} else {
			XSAny container = OpenSamlCompatibilityHelper.xsAnyBuilder
					.buildObject(SAMLConstants.SAML1_NS, AttributeValue.DEFAULT_ELEMENT_LOCAL_NAME, null);

			container.setTextContent(values.toString());
			attribute.getAttributeValues().add(container);
		}

		return attribute;
	}

	public static Subject buildNewSamlSubject(final String principalId) throws SAMLException {
		return OpenSamlCompatibilityHelper.buildSubject(principalId,
				OpenSamlCompatibilityHelper.ARTIFACT_CONF_METHOD_URI);
	}

	public static Subject buildSubject(final String nameIdentifierValue, final String confirmationMethodValue) {
		final Subject samlSubject =
				OpenSamlCompatibilityHelper.buildSamlObject(Subject.DEFAULT_ELEMENT_NAME);
		NameIdentifier nameIdentifier =
				OpenSamlCompatibilityHelper.buildSamlObject(NameIdentifier.DEFAULT_ELEMENT_NAME);
		samlSubject.setNameIdentifier(nameIdentifier);
		nameIdentifier.setNameIdentifier(nameIdentifierValue);

		final SubjectConfirmation subjectConfirmation =
				OpenSamlCompatibilityHelper.buildSamlObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		samlSubject.setSubjectConfirmation(subjectConfirmation);

		final ConfirmationMethod confirmationMethod =
				OpenSamlCompatibilityHelper.buildSamlObject(ConfirmationMethod.DEFAULT_ELEMENT_NAME);
		subjectConfirmation.getConfirmationMethods().add(confirmationMethod);
		confirmationMethod.setConfirmationMethod(confirmationMethodValue);

		return samlSubject;
	}

	public static Status buildStatus(final QName codeValue, final String statusMessage) {
		final Status status = OpenSamlCompatibilityHelper.buildSamlObject(Status.DEFAULT_ELEMENT_NAME);
		final StatusCode code = OpenSamlCompatibilityHelper.buildSamlObject(StatusCode.DEFAULT_ELEMENT_NAME);
		code.setValue(codeValue);
		status.setStatusCode(code);
		if (statusMessage != null) {
			final StatusMessage message = OpenSamlCompatibilityHelper.buildSamlObject(StatusMessage.DEFAULT_ELEMENT_NAME);
			message.setMessage(statusMessage);
			status.setStatusMessage(message);
		}
		return status;
	}

	@SuppressWarnings("unchecked")
	public static <T extends XMLObject> T buildSamlObject(final QName samlElement) {
		XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

		XMLObjectBuilder<XMLObject> builder = builderFactory.getBuilder(samlElement);
		QName qnameWithoutPrefix = new QName(samlElement.getNamespaceURI(), samlElement.getLocalPart());
		XMLObject samlObject = builder.buildObject(qnameWithoutPrefix);

		return (T) samlObject;
	}
}
