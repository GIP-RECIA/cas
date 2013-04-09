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

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.esco.cas.ISaml20Facade;
import org.esco.cas.impl.SamlAuthInfo;
import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.ISpConfig;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.ISaml20SpProcessor;
import org.esco.sso.security.saml.ISamlDataAdaptor;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.exception.SamlBuildingException;
import org.esco.sso.security.saml.impl.BasicSamlDataAdaptor;
import org.esco.sso.security.saml.om.IOutgoingSaml;
import org.esco.sso.security.saml.om.IRequestWaitingForResponse;
import org.esco.sso.security.saml.om.impl.SamlOutgoingMessage;
import org.esco.sso.security.saml.query.IQuery;
import org.esco.sso.security.saml.query.impl.QueryAuthnRequest;
import org.esco.sso.security.saml.query.impl.QuerySloRequest;
import org.esco.sso.security.saml.query.impl.QuerySloResponse;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * IdP Connector to authenticate people.
 * Use the IdP metadata to load certificates and SSO SAML2 HTTP-POST binding endpoint URL.
 * The authentication uses the Authn protocol :
 * - send a SAML 2 AuthnRequest
 * - wait for a SAML 2 AuthnResponse
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 * 
 */
public class OpenSaml20IdpConnector implements ISaml20IdpConnector, InitializingBean {

	/** Logger. */
	private final Logger logger = LoggerFactory.getLogger(OpenSaml20IdpConnector.class);

	/** This IdP configuration. */
	private IIdpConfig idpConfig;

	/** SP Processor. */
	private ISaml20SpProcessor spProcessor;

	/** SAML data adaptor. Configure the shape of SAML datas in HTTP request. */
	private ISamlDataAdaptor dataAdaptor;

	private AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();

	private RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();

	private IssuerBuilder issuerBuilder = new IssuerBuilder();

	private AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();

	private LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();

	private LogoutResponseBuilder logoutResponseBuilder = new LogoutResponseBuilder();

	@SuppressWarnings("unused")
	private SubjectBuilder subjectBuilder = new SubjectBuilder();

	private ConditionsBuilder conditionsBuilder = new ConditionsBuilder();

	private SessionIndexBuilder sessionIndexBuilder = new SessionIndexBuilder();

	@Override
	@SuppressWarnings("unchecked")
	public IOutgoingSaml buildSaml20AuthnRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlBuildingException {
		this.logger.debug("Building new SAML 2.0 Authentication Request ...");

		final AuthnRequest authnRequest = this.buildAuthnRequest(binding);

		final IOutgoingSaml outgoingSaml;
		try {
			final QueryAuthnRequest samlQuery = this.buildQueryAuthnRequest(request.getParameterMap());
			final String ssoEndpointUrl = this.idpConfig.getIdpSsoEndpointUrl(binding);
			outgoingSaml = this.buildSamlOutgoingRequest(samlQuery, authnRequest, binding, ssoEndpointUrl);
			this.getSaml20SpProcessor().storeRequestWaitingForResponseInCache(samlQuery);

		} catch (MarshallingException e) {
			throw new SamlBuildingException("Unable to build SAML 2.0 AuthnRequest !", e);
		} catch (SignatureException e) {
			throw new SamlBuildingException("Unable to sign SAML 2.0 AuthnRequest !", e);
		}

		return outgoingSaml;
	}

	@Override
	public IOutgoingSaml buildSaml20SingleLogoutRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlBuildingException {
		this.logger.debug("Building new SAML 2.0 Single Logout Request ...");

		ISaml20SpProcessor spProc = this.getSaml20SpProcessor();
		ISaml20Facade samlFacade = spProc.getSaml20Facade();

		String tgtId = samlFacade.retrieveTgtIdFromCookie(request);
		Assert.notNull(tgtId, "CAS TGT Id cannot be null here !");
		SamlAuthInfo authInfos = samlFacade.retrieveAuthenticationInfosFromCache(tgtId);
		Assert.notNull(authInfos, "SAML auth informations cannot be null here !");

		final LogoutRequest logoutRequest = this.buildLogoutRequest(binding, authInfos);

		final IOutgoingSaml outgoingSaml;
		try {
			final QuerySloRequest samlQuery = this.buildQuerySloRequest();
			final String sloEndpointUrl = this.idpConfig.getIdpSloEndpointUrl(binding);
			outgoingSaml = this.buildSamlOutgoingRequest(samlQuery, logoutRequest, binding, sloEndpointUrl);
			this.getSaml20SpProcessor().storeRequestWaitingForResponseInCache(samlQuery);

		} catch (MarshallingException e) {
			throw new SamlBuildingException("Unable to build SAML 2.0 SLO Request !", e);
		} catch (SignatureException e) {
			throw new SamlBuildingException("Unable to sign SAML 2.0 SLO Request !", e);
		}

		return outgoingSaml;
	}

	@Override
	public IOutgoingSaml buildSaml20SingleLogoutResponse(final SamlBindingEnum binding,
			final String originRequestId, final String relayState) throws SamlBuildingException {
		this.logger.debug("Building new SAML 2.0 Single Logout Response ...");

		LogoutResponse logoutResponse = this.buildLogoutResponse(binding);

		final IOutgoingSaml outgoingSaml;
		try {
			final IQuery samlQuery = this.buildQuerySloResponse(originRequestId);
			final String sloEndpointUrl = this.idpConfig.getIdpSloEndpointUrl(binding);
			outgoingSaml = this.buildSamlOutgoingMessage(samlQuery, logoutResponse, binding, relayState, sloEndpointUrl);

		} catch (MarshallingException e) {
			throw new SamlBuildingException("Unable to build SAML 2.0 SLO Response !", e);
		} catch (SignatureException e) {
			throw new SamlBuildingException("Unable to sign SAML 2.0 SLO Response !", e);
		}

		return outgoingSaml;
	}

	@Override
	public void registerSaml20SpProcessor(final ISaml20SpProcessor saml20SpProcessor) {
		this.spProcessor = saml20SpProcessor;
	}

	protected ISaml20SpProcessor getSaml20SpProcessor() {
		Assert.notNull(this.spProcessor, String.format("No SAML 2.0 SP processor was bind to IdP %1$s !", this.getIdpConfig().getId()));

		return this.spProcessor;
	}

	/**
	 * Prepare a new SAML 2.0 outgoing request to send to IdP with a new generated relayState.
	 * 
	 * @param samlQuery SAML query object
	 * @param request the opensaml object to marshall
	 * @param binding the binding to use
	 * @param relayState
	 * @return samlOutgoingMessage the outgoing message to send
	 * @throws MarshallingException
	 * @throws SignatureException
	 */
	protected SamlOutgoingMessage buildSamlOutgoingRequest(final IRequestWaitingForResponse samlQuery,
			final RequestAbstractType request, final SamlBindingEnum binding, final String endpointUrl)
					throws MarshallingException, SignatureException {
		request.setID(samlQuery.getId());

		final String relayState = OpenSamlHelper.generateRelayState(
				this.getIdpConfig().getId(), binding);

		return this.buildSamlOutgoingMessage(samlQuery, request, binding, relayState, endpointUrl);
	}

	/**
	 * Prepare a new SAML 2.0 message to send to IdP.
	 * 
	 * @param samlObject the opensaml object to marshall
	 * @param binding the binding to use
	 * @param relayState
	 * @return samlOutgoingMessage the outgoing message to send
	 * @throws MarshallingException
	 * @throws SignatureException
	 */
	protected SamlOutgoingMessage buildSamlOutgoingMessage(final IQuery samlQuery,
			final SAMLObject samlObject, final SamlBindingEnum binding, final String relayState, final String endpointUrl)
					throws MarshallingException, SignatureException {
		Assert.notNull(samlQuery, "No SAML Query provided !");
		Assert.notNull(samlObject, "No OpenSaml object provided !");
		Assert.notNull(binding, "No binding provided !");

		final SamlOutgoingMessage samlOutgoingMessage = new SamlOutgoingMessage(this.dataAdaptor);

		// SAML Query
		samlOutgoingMessage.setSamlQuery(samlQuery);

		// Relay State
		samlOutgoingMessage.setRelayState(relayState);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(String.format("Random RelayState: %s", relayState));
		}

		// MBD bug : Forgot to sign the SAML Object
		// Xml Message
		final String xmlLogoutResponse;
		if (SignableSAMLObject.class.isAssignableFrom(samlObject.getClass())) {
			final SignableSAMLObject signableSamlObject = (SignableSAMLObject) samlObject;
			xmlLogoutResponse = OpenSamlHelper.marshallSignableSamlObject(signableSamlObject);
		} else {
			xmlLogoutResponse = OpenSamlHelper.marshallXmlObject(samlObject);
		}

		samlOutgoingMessage.setSamlMessage(xmlLogoutResponse);
		samlOutgoingMessage.setEndpointUrl(endpointUrl);

		return samlOutgoingMessage;
	}

	/**
	 * Build a SAML Authn Request query.
	 * 
	 * @param parametersMap
	 * @return
	 */
	protected QueryAuthnRequest buildQueryAuthnRequest(final Map<String, String[]> parametersMap) {
		final String generatedUniqueId = this.generateUniqueQueryId();
		final QueryAuthnRequest query = new QueryAuthnRequest(generatedUniqueId, this, parametersMap);

		return query;
	}

	/**
	 * Build a SAML SLO Request query.
	 * 
	 * @return
	 */
	protected QuerySloRequest buildQuerySloRequest() {
		final String generatedUniqueId = this.generateUniqueQueryId();
		final QuerySloRequest query = new QuerySloRequest(generatedUniqueId,this);

		return query;
	}

	/**
	 * Build SAML SLO Response query.
	 * 
	 * @param inResponseToId
	 * @return
	 */
	protected QuerySloResponse buildQuerySloResponse(final String inResponseToId) {
		final String generatedUniqueId = this.generateUniqueQueryId();
		final QuerySloResponse query = new QuerySloResponse(generatedUniqueId);
		query.setInResponseToId(inResponseToId);

		return query;
	}

	/**
	 * Generate a unique ID for a SAML query.
	 * 
	 * @return the unique ID
	 */
	protected String generateUniqueQueryId() {
		String randId = OpenSamlHelper.generateRandomHexString(42);

		this.logger.debug("Random ID: {}", randId);

		return randId;
	}

	/**
	 * Build a SAML2 authentication request.
	 * 
	 * @param requestId the request Id
	 * @return the authentication request
	 */
	protected AuthnRequest buildAuthnRequest(final SamlBindingEnum binding) {
		Issuer issuer = this.buildIssuer();

		// Create NameIDPolicy
		NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
		NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
		nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		nameIdPolicy.setAllowCreate(false);

		// Create AuthnContextClassRef
		AuthnContextClassRef authnContextClassRef = this.authnContextClassRefBuilder
				.buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextClassRef.setAuthnContextClassRef(
				"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		// Create RequestedAuthnContext
		RequestedAuthnContext requestedAuthnContext = this.requestedAuthnContextBuilder
				.buildObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
		requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

		DateTime issueInstant = new DateTime();
		AuthnRequest authnRequest = this.authRequestBuilder.buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);

		// Force IdP authentication.
		authnRequest.setForceAuthn(this.idpConfig.isForceAuthentication());
		authnRequest.setIsPassive(false);
		authnRequest.setIssueInstant(issueInstant);

		SamlBindingEnum responseBinding = this.idpConfig.getResponseBinding();
		authnRequest.setProtocolBinding(responseBinding.getUri());
		ISpConfig spConfig = this.getSaml20SpProcessor().getSpConfig();
		authnRequest.setAssertionConsumerServiceURL(spConfig.getEndpointUrl(responseBinding));

		authnRequest.setIssuer(issuer);
		authnRequest.setNameIDPolicy(nameIdPolicy);
		//authnRequest.setRequestedAuthnContext(requestedAuthnContext);
		//authnRequest.setProviderName(this.spConfig.getEntityId());
		authnRequest.setDestination(this.idpConfig.getIdpSsoEndpointUrl(binding));
		authnRequest.setVersion(SAMLVersion.VERSION_20);

		// Select the Attributes to be returned
		if (this.idpConfig.getAttributeConsumingServiceIndex() != null) {
			authnRequest.setAttributeConsumingServiceIndex(this.idpConfig.getAttributeConsumingServiceIndex());
		}

		//Subject subject = this.subjectBuilder.buildObject();
		//authnRequest.setSubject(subject);

		// Time validity window : + or - XX ms
		Conditions conditions = this.conditionsBuilder.buildObject();
		conditions.setNotBefore(this.buildNotBeforeTime(issueInstant));
		conditions.setNotOnOrAfter(this.buildNotOnOrAfterTime(issueInstant));
		authnRequest.setConditions(conditions);

		this.getSaml20SpProcessor().signSamlObject(authnRequest);

		return authnRequest;
	}

	/**
	 * Build a SAML2 Single Logout Request.
	 * 
	 * @return the authentication request
	 * @throws SamlBuildingException
	 */
	protected LogoutRequest buildLogoutRequest(final SamlBindingEnum binding,
			final SamlAuthInfo authInfos) throws SamlBuildingException {
		DateTime issueInstant = new DateTime();
		LogoutRequest  logoutRequest = this.logoutRequestBuilder.buildObject(LogoutRequest.DEFAULT_ELEMENT_NAME);

		logoutRequest.setIssueInstant(issueInstant);
		logoutRequest.setIssuer(this.buildIssuer());
		logoutRequest.setDestination(this.idpConfig.getIdpSloEndpointUrl(binding));
		logoutRequest.setVersion(SAMLVersion.VERSION_20);
		logoutRequest.setNotOnOrAfter(this.buildNotOnOrAfterTime(issueInstant));

		String subjectId = authInfos.getIdpSubject();
		if (!StringUtils.hasText(subjectId)) {
			// We don't know the subject so we cannot build a logout request
			throw new SamlBuildingException("No SAML 2.0 Subject can be found to build the Single Logout Request !");
		}

		NameIDBuilder builder = new NameIDBuilder();
		NameID newNameId = builder.buildObject(NameID.DEFAULT_ELEMENT_NAME);
		newNameId.setValue(subjectId);
		logoutRequest.setNameID(newNameId);

		String sessionIndex = authInfos.getSessionIndex();
		if (StringUtils.hasText(sessionIndex)) {
			SessionIndex sessionIndexObj = this.sessionIndexBuilder.buildObject(SessionIndex.DEFAULT_ELEMENT_NAME);
			sessionIndexObj.setSessionIndex(sessionIndex);
			logoutRequest.getSessionIndexes().add(sessionIndexObj);
		}

		this.getSaml20SpProcessor().signSamlObject(logoutRequest);

		return logoutRequest;
	}

	/**
	 * Build a SAML2 Single Logout Response.
	 * 
	 * @param binding the request binding
	 * @return the authentication request
	 */
	protected LogoutResponse buildLogoutResponse(final SamlBindingEnum binding) {
		DateTime issueInstant = new DateTime();
		LogoutResponse  logoutResponse = this.logoutResponseBuilder.buildObject(LogoutResponse.DEFAULT_ELEMENT_NAME);

		logoutResponse.setIssueInstant(issueInstant);
		logoutResponse.setIssuer(this.buildIssuer());

		logoutResponse.setDestination(this.idpConfig.getIdpSloEndpointUrl(binding));
		logoutResponse.setVersion(SAMLVersion.VERSION_20);

		this.getSaml20SpProcessor().signSamlObject(logoutResponse);

		return logoutResponse;
	}

	/**
	 * Build the NotBefore time considering the time validity window parameter.
	 * 
	 * @param issueInstant the request issue instant
	 * @return the NotBefore time
	 */
	protected DateTime buildNotBeforeTime(final DateTime issueInstant) {
		return issueInstant.minus(this.idpConfig.getTimeValidityWindow());
	}

	/**
	 * Build the NotOnOrAfter time considering the time validity window parameter.
	 * 
	 * @param issueInstant the request issue instant
	 * @return the NotOnOrAfter time
	 */
	protected DateTime buildNotOnOrAfterTime(final DateTime issueInstant) {
		return issueInstant.plus(this.idpConfig.getTimeValidityWindow());
	}

	protected Issuer buildIssuer() {
		// Create an issuer Object
		Issuer issuer = this.issuerBuilder.buildObject();
		ISpConfig spConfig = this.getSaml20SpProcessor().getSpConfig();
		issuer.setValue(spConfig.getEntityId());
		return issuer;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		DefaultBootstrap.bootstrap();

		Assert.notNull(this.idpConfig, "No IdP config provided for IdP connector !");
		this.idpConfig.registerSaml20IdpConnector(this);

		if (this.dataAdaptor == null) {
			this.dataAdaptor = new BasicSamlDataAdaptor();
		}

	}

	@Override
	public IIdpConfig getIdpConfig() {
		return this.idpConfig;
	}

	public void setIdpConfig(final IIdpConfig idpConfig) {
		this.idpConfig = idpConfig;
	}

	public void setDataAdaptor(final ISamlDataAdaptor dataAdaptor) {
		this.dataAdaptor = dataAdaptor;
	}

}
