/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.cas.ISaml20Facade;
import org.esco.cas.impl.SamlAuthInfo;
import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.ISpConfig;
import org.esco.sso.security.saml.BasicSamlDataAdaptor;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.ISaml20SpProcessor;
import org.esco.sso.security.saml.ISamlDataAdaptor;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.SamlBuildingException;
import org.esco.sso.security.saml.SamlRequestData;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.BaseID;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;
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
	private final Log logger = LogFactory.getLog(OpenSaml20IdpConnector.class);

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
	public SamlRequestData buildSaml20AuthnRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) {
		this.logger.debug("Building new SAML 2.0 Authentication Request ...");

		AuthnRequest authnRequest = this.buildAuthnRequest(binding);

		SamlRequestData samlAuthRequestData = this.prepareNewSamlRequest(authnRequest,
				request, binding);

		ISaml20SpProcessor spProc = this.getSaml20SpProcessor();
		String encodedAuthnRequest = spProc.encodeSamlObject(binding, authnRequest);
		samlAuthRequestData.setSamlRequest(encodedAuthnRequest);
		samlAuthRequestData.setEndpointUrl(this.idpConfig.getIdpSsoEndpointUrl(binding));

		this.getSaml20SpProcessor().storeSamlRequestDataInCache(samlAuthRequestData);

		return samlAuthRequestData;
	}

	@Override
	public SamlRequestData buildSaml20SingleLogoutRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlBuildingException {
		this.logger.debug("Building new SAML 2.0 Single Logout Request ...");

		ISaml20SpProcessor spProc = this.getSaml20SpProcessor();
		ISaml20Facade samlFacade = spProc.getSaml20Facade();

		String tgtId = samlFacade.retrieveTgtIdFromCookie(request);
		Assert.notNull(tgtId, "CAS TGT Id cannot be null here !");
		SamlAuthInfo authInfos = samlFacade.retrieveAuthenticationInfosFromCache(tgtId);
		Assert.notNull(authInfos, "SAML auth informations cannot be null here !");

		LogoutRequest logoutRequest = this.buildLogoutRequest(binding, authInfos);
		SamlRequestData samlLogoutRequestData = this.prepareNewSamlRequest(logoutRequest,
				request, binding);

		String encodedLogoutRequest = spProc.encodeSamlObject(binding, logoutRequest);
		samlLogoutRequestData.setSamlRequest(encodedLogoutRequest);
		samlLogoutRequestData.setEndpointUrl(this.idpConfig.getIdpSloEndpointUrl(binding));

		this.getSaml20SpProcessor().storeSamlRequestDataInCache(samlLogoutRequestData);

		return samlLogoutRequestData;
	}

	@Override
	public SamlRequestData buildSaml20SingleLogoutResponse(final SamlBindingEnum binding,
			final String originRequestId) {
		this.logger.debug("Building new SAML 2.0 Single Logout Response ...");

		LogoutResponse logoutResponse = this.buildLogoutResponse(binding);
		SamlRequestData samlLogoutRequestData = this.prepareNewSamlResponse(logoutResponse,
				binding, originRequestId);

		ISaml20SpProcessor spProc = this.getSaml20SpProcessor();
		String encodedLogoutResponse = spProc.encodeSamlObject(binding, logoutResponse);
		samlLogoutRequestData.setSamlRequest(encodedLogoutResponse);
		samlLogoutRequestData.setEndpointUrl(this.idpConfig.getIdpSloEndpointUrl(binding));

		// No need to store a SLO Response request !
		//this.getSaml20SpProcessor().storeSamlRequestDataInCache(samlLogoutRequestData);

		return samlLogoutRequestData;
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
	 * Prepare a new SAML 2.0 Request to fit the CAS HTTP Request.
	 * 
	 * @param newRequest the new SAML 2.0 request
	 * @param request the HTTP request
	 * @param binding the binding for the SAML 2.0 request
	 * @return the builded SAML Request Data
	 */
	@SuppressWarnings("unchecked")
	protected SamlRequestData prepareNewSamlRequest(final RequestAbstractType newRequest, final HttpServletRequest request,
			final SamlBindingEnum binding) {
		SamlRequestData samlRequestData = this.buildSamlRequestData();

		Assert.notNull(newRequest, "No SAML Request provided !");
		Assert.notNull(binding, "No binding provided !");

		samlRequestData.setParametersMap(request.getParameterMap());

		// Generate ID
		String randId = OpenSamlHelper.generateRandomHexString(42);
		samlRequestData.setId(randId);
		newRequest.setID(randId);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(String.format("Random ID: %s", randId));
		}

		// Relay State
		String relayState = OpenSamlHelper.generateRelayState(0, binding);
		samlRequestData.setRelayState(relayState);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(String.format("Random RelayState: %s", relayState));
		}

		return samlRequestData;
	}

	/**
	 * Prepare a new SAML 2.0 Request to fit the CAS HTTP Request.
	 * 
	 * @param newRequest the new SAML 2.0 request
	 * @param binding the binding for the SAML 2.0 request
	 * @param originRequestId the original request Id
	 * @return the builded SAML Request Data
	 */
	protected SamlRequestData prepareNewSamlResponse(final StatusResponseType newResponse,
			final SamlBindingEnum binding, final String originRequestId) {
		SamlRequestData samlRequestData = this.buildSamlRequestData();

		Assert.notNull(newResponse, "No SAML Response provided !");
		Assert.notNull(binding, "No binding provided !");

		// Generate ID
		String randId = OpenSamlHelper.generateRandomHexString(42);
		samlRequestData.setId(randId);
		newResponse.setID(randId);
		newResponse.setInResponseTo(originRequestId);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(String.format("Random ID: %s", randId));
		}

		// Relay State
		String relayState = OpenSamlHelper.generateRelayState(0, binding);
		samlRequestData.setRelayState(relayState);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(String.format("Random RelayState: %s", relayState));
		}

		return samlRequestData;
	}

	/**
	 * Build a SAML Request Data object.
	 * 
	 * @return the SAML Request Data
	 */
	protected SamlRequestData buildSamlRequestData() {
		SamlRequestData requestData = new SamlRequestData(this, this.dataAdaptor);

		return requestData;
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

		this.getSaml20SpProcessor().signSamlObject(authnRequest);

		//Subject subject = this.subjectBuilder.buildObject();
		//authnRequest.setSubject(subject);

		// Time validity window : + or - XX ms
		Conditions conditions = this.conditionsBuilder.buildObject();
		conditions.setNotBefore(this.buildNotBeforeTime(issueInstant));
		conditions.setNotOnOrAfter(this.buildNotOnOrAfterTime(issueInstant));
		authnRequest.setConditions(conditions);

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

		Subject subject = authInfos.getIdpSubject();
		if (subject == null) {
			// We don't know the subject so we cannot build a logout request
			throw new SamlBuildingException("No SAML 2.0 Subject can be found to build the Single Logout Request !");
		}
		Assert.notNull(subject, "SAML Subject cannot be null here !");

		NameID nameId = subject.getNameID();
		if (nameId != null) {
			NameIDBuilder builder = new NameIDBuilder();
			NameID newNameId = builder.buildObject(NameID.DEFAULT_ELEMENT_NAME);
			newNameId.setFormat(nameId.getFormat());
			newNameId.setValue(nameId.getValue());
			newNameId.setNameQualifier(nameId.getNameQualifier());
			logoutRequest.setNameID(newNameId);
		}
		BaseID baseId = subject.getBaseID();
		if (baseId != null) {
			baseId.detach();
			logoutRequest.setBaseID(baseId);
		}

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
