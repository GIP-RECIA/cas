/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import net.sf.ehcache.CacheException;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.Validate;
import org.esco.cas.ISaml20Facade;
import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.ISpConfig;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.ISaml20SpProcessor;
import org.esco.sso.security.saml.NotSignedException;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.SamlHelper;
import org.esco.sso.security.saml.SamlProcessingException;
import org.esco.sso.security.saml.SamlRequestData;
import org.esco.sso.security.saml.SamlResponseData;
import org.jasig.cas.CentralAuthenticationService;
import org.joda.time.DateTime;
import org.joda.time.Instant;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.common.binding.security.MessageReplayRule;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.util.storage.ReplayCache;
import org.opensaml.util.storage.ReplayCacheEntry;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureTrustEngine;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class OpenSaml20SpProcessor implements ISaml20SpProcessor, InitializingBean {

	/** Logger. */
	private final Logger logger = LoggerFactory.getLogger(OpenSaml20SpProcessor.class);

	/** SAML 2.0 Request Data cache name. */
	private static final String SAML2_REQUEST_DATA_CACHE_NAME = "samlRequestDataCache";

	/** SAML 2.0 Response Data cache name. */
	private static final String SAML2_RESPONSE_DATA_CACHE_NAME = "samlResponseDataCache";

	/** SP Configuration. */
	private ISpConfig spConfig;

	/** Decrypt responses encrypted assertions with spCertificate. */
	private Decrypter decrypter;

	/** Signature builder. */
	private SignatureBuilder signatureBuilder = new SignatureBuilder();

	/** SP Signing credentials (spSigningKey + spSigningCertificate). */
	private Credential spSigningCredential;

	/** SAML Message Decoder (Base64, inflater, ...). */
	private Map<SamlBindingEnum, SAMLMessageDecoder> samlMessageDecoders;

	private SAMLSignatureProfileValidator signatureProfileValidator;

	private MessageReplayRule rule;

	private int replayMinutes;

	/** Acceptable clock skew. */
	private int clockSkewSeconds;

	/** SAML Request cache. */
	private Ehcache samlRequestDataCache;

	/** SAML Response cache. */
	private Ehcache samlResponseDataCache;

	/** IdP connectors. */
	private Collection<ISaml20IdpConnector> idpConnectors;

	/** Map of IdP connectors indexed by their entity Id. */
	private Map<String, ISaml20IdpConnector> idpConnectorsByEntityId = new HashMap<String, ISaml20IdpConnector>();

	/** SAML 2.0 Facade. */
	private ISaml20Facade samlFacade;

	/** CAS service. */
	private CentralAuthenticationService cas;

	@Override
	public SamlResponseData processSaml20IncomingRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlProcessingException {
		SamlResponseData response = null;

		// Retrieve SAML Object from HTTP request
		final SAMLObject samlObject;
		try {
			samlObject = this.extractSamlObjectFromRequest(request, binding);
			final ISaml20IdpConnector idpConnector = this.findSaml20IdpConnectorToUse(samlObject);

			Assert.notNull(idpConnector, "The IdPConnector cannot be null here !");

			this.logger.debug(String.format(
					"Incoming SAML request use the IdP connector with id [%s] .",
					idpConnector.getIdpConfig().getId()));

			// Process the SAML Object
			if (Response.class.isAssignableFrom(samlObject.getClass())) {
				// Process Authn Response
				response = this.processSaml20AuthnResponse((Response)samlObject, binding, idpConnector);
			} else {
				throw new SamlProcessingException(String.format("Unsupported SAML query type: [%s] !",
						samlObject.getClass().getName()));
			}
		} catch (MessageDecodingException e) {
			this.logger.debug("Error while extracting SAML message from request !", e);
			throw new SamlProcessingException("Error while extracting SAML message from request !", e);
		} catch (SecurityException e) {
			this.logger.debug("Security problem while extracting SAML message from request !", e);
			throw new SamlProcessingException("Security problem while extracting SAML message from request !", e);
		} catch (ValidationException e) {
			this.logger.debug("SAML request validation problem !", e);
			throw new SamlProcessingException("SAML request validation problem  problem !", e);
		} catch (DecryptionException e) {
			this.logger.debug("Error while decrypting encrypted SAML parts !", e);
			throw new SamlProcessingException("Error while decrypting encrypted SAML parts !", e);
		}

		return response;
	}

	@Override
	public SamlResponseData processSaml20IncomingSingleLogoutRequest(final HttpServletRequest request,
			final SamlBindingEnum binding) throws SamlProcessingException {
		SamlResponseData response = null;

		try {
			// Retrieve SAML Object from HTTP request
			SAMLObject samlObject = this.extractSamlObjectFromRequest(request, binding);
			ISaml20IdpConnector idpConnector = this.findSaml20IdpConnectorToUse(samlObject);

			Assert.notNull(idpConnector, "The IdPConnector cannot be null here !");

			this.logger.debug(String.format(
					"Incoming SAML logout request use the IdP connector with id [%s] .",
					idpConnector.getIdpConfig().getId()));

			// Process the SAML Object
			if (LogoutRequest.class.isAssignableFrom(samlObject.getClass())) {
				// Process SLO Request
				response = this.processSaml20SingleLogoutRequest((LogoutRequest)samlObject, binding, idpConnector);
			} else if (LogoutResponse.class.isAssignableFrom(samlObject.getClass())) {
				//Process SLO Response
				response = this.processSaml20SingleLogoutResponse((LogoutResponse)samlObject, binding, idpConnector);
			} else {
				throw new SamlProcessingException(String.format("Unsupported SAML query type: [%s] !",
						samlObject.getClass().getName()));
			}

		} catch (MessageDecodingException e) {
			this.logger.debug("Error while extracting SAML message from request !", e);
			throw new SamlProcessingException("Error while extracting SAML message from request !", e);
		} catch (SecurityException e) {
			this.logger.debug("Security problem while extracting SAML message from request !", e);
			throw new SamlProcessingException("Security problem while extracting SAML message from request !", e);
		} catch (ValidationException e) {
			this.logger.debug("SAML request validation problem  problem !", e);
			throw new SamlProcessingException("SAML request validation problem  problem !", e);
		} catch (NotSignedException e) {
			this.logger.debug("SAML Logout Response signature missing !", e);
			throw new SamlProcessingException("SAML Logout Response signature missing !", e);
		}

		return response;
	}

	@Override
	public ISaml20IdpConnector findSaml20IdpConnectorToUse(final String idpEntityId) {
		return this.idpConnectorsByEntityId.get(idpEntityId);
	}

	@Override
	public String encodeSamlObject(final SamlBindingEnum binding, final SignableSAMLObject samlObject) {
		String encodedAuthnRequest = null;
		try {
			switch (binding) {
			case SAML_20_HTTP_POST:
				encodedAuthnRequest = OpenSamlHelper.httpPostEncode(samlObject);
				break;
			case SAML_20_HTTP_REDIRECT:
				encodedAuthnRequest = OpenSamlHelper.httpRedirectEncode(samlObject);
				break;
			}
		} catch (UnsupportedEncodingException e) {
			this.logger.error("Error while encoding SAML 2.0 AuthnRequest !", e);
		} catch (IOException e) {
			this.logger.error("Error while encoding SAML 2.0 AuthnRequest !", e);
		}
		Assert.notNull(encodedAuthnRequest, "Error while encoding authn request !");
		return encodedAuthnRequest;
	}

	@Override
	public SamlResponseData getCachedSaml20Response(final String relayState) {
		SamlResponseData result = null;
		if (relayState != null) {
			Element element = this.samlResponseDataCache.get(relayState);
			if (element != null) {
				result = (SamlResponseData) element.getObjectValue();
			}
		}
		return result;
	}

	/**
	 * Store a SAML Request Data in the cache.
	 * 
	 * @param requestData the Request Data to store
	 */
	@Override
	public void storeSamlRequestDataInCache(final SamlRequestData requestData) {
		Assert.notNull(requestData, "Trying to store a null request in cache !");
		Assert.notNull(requestData.getId(), "Trying to store a request without Id in cache !");
		this.samlRequestDataCache.put(new Element(requestData.getId(), requestData));
	}

	@Override
	public ISaml20Facade getSaml20Facade() {
		return this.samlFacade;
	}

	@Override
	public Decrypter getDecrypter() {
		return this.decrypter;
	}

	@Override
	public ISpConfig getSpConfig() {
		return this.spConfig;
	}

	@Override
	public Signature signSamlObject(final SignableSAMLObject signable) {
		Signature newSignature = this.buildSignature();

		signable.setSignature(newSignature);
		return newSignature;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.samlFacade, "The SAML 2.0 Facade wasn't injected !");
		Assert.notNull(this.cas, "The CAS service wasn't injected !");
		Assert.notNull(this.getSpConfig(), "No SP configuration provided for this SP processor !");

		//TODO MBD: what to do with this ?
		StorageService<String, ReplayCacheEntry> storageEngine = new MapBasedStorageService<String, ReplayCacheEntry>();
		ReplayCache replayCache = new ReplayCache(storageEngine, 60 * 1000 * this.replayMinutes);
		this.rule = new MessageReplayRule(replayCache);

		Assert.notNull(this.samlMessageDecoders, "No SAML message decoders provided for this IdP connector !");
		for (SamlBindingEnum binding : SamlBindingEnum.values()) {
			Assert.notNull(this.samlMessageDecoders.get(binding),
					String.format("No SAML message decoder provided for the binding [%s] !",
							binding.getDescription()));
		}

		// Retrieve IdP connectors and
		// Register this SP processor in the IdP connectors
		Assert.notEmpty(this.idpConnectors, "No IdP connector injected in the SP processor !");
		for (ISaml20IdpConnector idpConnector: this.idpConnectors) {
			try {
				idpConnector.registerSaml20SpProcessor(this);
				this.idpConnectorsByEntityId.put(idpConnector.getIdpConfig().getIdpEntityId(), idpConnector);
			} catch (IllegalAccessError e) {
				// Catch exception thrown by fake IdPs like CAS Fake IdP.
			}
		}

		this.spSigningCredential = SecurityHelper.getSimpleCredential(
				this.getSpConfig().getSigningCredential().getPublicKey(),
				this.getSpConfig().getSigningKey());
		Assert.notNull(this.spSigningCredential, "Unable to build SP signing credentials (signing public + private keys) !");

		this.decrypter = this.buildDecrypter();

		this.initCaches();

		// Register this processor in the Helper
		SamlHelper.registerSpProcessor(this);
	}

	/**
	 * Store a SAML Response Data in the cache.
	 * To store a response, a request need to be already present in request cache !
	 * Remove the Request Data from request cache.
	 * 
	 * @param responseData the Response Data to store
	 */
	protected void storeSamlResponseDataInCache(final SamlResponseData responseData)
			throws SamlProcessingException {

		SamlRequestData authnRequestData;

		String uniqueId = responseData.getInResponseToId();
		Assert.notNull(uniqueId, "SAML Response cannot have a null  unique ID !");

		// Get request from cache
		Element element = this.samlRequestDataCache.get(uniqueId);
		if (element != null) {
			authnRequestData = (SamlRequestData) element.getObjectValue();
		} else {
			throw new SamlProcessingException("No Authn Request corresponding to the Authn Response found !");
		}

		// Clear request from cache
		this.samlRequestDataCache.remove(uniqueId);

		responseData.setOriginalRequestData(authnRequestData);
	}


	/**
	 * Find the SAML 2.0 IdP Connector to use to process the SAML Object.
	 * 
	 * @param samlObject the SAML 2.0 object to process
	 * @return the SAML 2.0 IdP connector attached
	 * @throws SamlProcessingException if no IdP connector found
	 */
	protected ISaml20IdpConnector findSaml20IdpConnectorToUse(final SAMLObject samlObject)
			throws SamlProcessingException {
		ISaml20IdpConnector samlConnector = null;

		Assert.notNull(samlObject, "No signable SAML objet provided !");

		if (StatusResponseType.class.isAssignableFrom(samlObject.getClass())) {
			// The SAML object is a Response, so the original request must be in the cache !
			StatusResponseType samlResponse = (StatusResponseType) samlObject;
			String originalRequestId = samlResponse.getInResponseTo();

			if (StringUtils.hasText(originalRequestId)) {
				Element element = this.samlRequestDataCache.get(originalRequestId);
				if (element != null) {
					Object value = element.getValue();
					if (value != null) {
						SamlRequestData originalRequestData = (SamlRequestData) element.getValue();
						samlConnector = originalRequestData.getIdpConnectorBuilder();
					}
				}
			}

		} else if (RequestAbstractType.class.isAssignableFrom(samlObject.getClass())) {
			// Search IdPConnector by Issuer
			RequestAbstractType samlRequest = (RequestAbstractType) samlObject;

			Issuer issuer = samlRequest.getIssuer();
			if (issuer != null) {
				String issuerEntityId = issuer.getValue();
				this.idpConnectorsByEntityId.get(issuerEntityId);
				//FIXME: Not implemented yet
			}

		}

		if (samlConnector == null) {
			throw new SamlProcessingException(
					"Unable to find an IdP Connector to process the SAML request !");
		}

		return samlConnector;
	}

	@SuppressWarnings("unchecked")
	protected SamlResponseData processSaml20AuthnResponse(final Response authnResponse,
			final SamlBindingEnum binding, final ISaml20IdpConnector idpConnector) throws SamlProcessingException,
			ValidationException, DecryptionException {
		Assert.notNull(authnResponse, "Authn Response must be supplied !");
		this.logger.debug("Processing a SAML 2.0 Response...");

		SamlResponseData samlResponseData = new SamlResponseData();

		try {
			String messageXML = OpenSamlHelper.marshallXmlObject(authnResponse);
			samlResponseData.setSamlResponse(messageXML);

			// Logging XML Authn Response
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(String.format("SAML Authn Response: %s", messageXML));
			}
		} catch (MarshallingException e) {
			this.logger.warn("Error while marshalling SAML 2.0 Authn Response !", e);
		}

		Map<String, List<String>> attributesMap = new HashMap<String, List<String>>();

		// Validate Response signature
		boolean responseSigned = false;
		try {
			this.validateResponseSignatureTrust(authnResponse, idpConnector);
			responseSigned = true;
		} catch (NotSignedException e) {
			// If the response signature is absent, try to check assertions signature...
			this.logger.debug("Unable to validate Response signature trust ! We will try to validate the assertions signatures ...", e);
		}

		final Decrypter decrypter = this.getDecrypter();

		for (Assertion assertion : this.retrieveAllAssertions(authnResponse, decrypter)) {
			this.validateConditions(assertion);

			try {
				this.validateAssertionSignatureTrust(assertion, idpConnector);
			} catch (NotSignedException e) {
				this.logger.debug("Unable to validate Assertion signature trust !", e);

				if (!responseSigned) {
					// if nether response or assertion are signed => validation exception
					throw new ValidationException("SAML Authn Response signature missing !");
				}
			}

			Subject subject = this.validateAndRetrieveSubject(assertion);
			samlResponseData.setSamlSubject(subject);

			String sessionIndex = this.retrieveSessionIndex(assertion);
			samlResponseData.setSessionIndex(sessionIndex);

			this.processAssertionAttributes(assertion, attributesMap);
		}

		attributesMap = MapUtils.unmodifiableMap(attributesMap);
		final IIdpConfig config = idpConnector.getIdpConfig();
		this.logger.info("IdP [{}] with Id: [{}] succesfully returned a SAML AuthnResponse with attributes: [{}].",
				new Object[]{config.getIdpEntityId(), config.getId(), attributesMap});

		samlResponseData.setAttributes(attributesMap);
		samlResponseData.setId(authnResponse.getID());
		samlResponseData.setInResponseToId(authnResponse.getInResponseTo());

		this.storeSamlResponseDataInCache(samlResponseData);

		this.logger.debug("SAML 2.0 Authn Response processing ended.");
		return samlResponseData;
	}

	/**
	 * Process a SLO Request.
	 * 
	 * @param request the HTTP request
	 * @param binding the SLO Request binding
	 * @return the SLO Response to return to the IdP
	 * @throws SamlProcessingException
	 */
	protected SamlResponseData processSaml20SingleLogoutRequest(final LogoutRequest logoutRequest,
			final SamlBindingEnum binding, final ISaml20IdpConnector idpConnector) throws SamlProcessingException {
		Assert.notNull(logoutRequest, "SLO Request must be supplied !");
		this.logger.debug("Processing a SAML 2.0 Single Logout Request...");

		// Logout
		this.logoutFromCas(logoutRequest.getNameID());

		String originRequestId = logoutRequest.getID();
		SamlRequestData sloResponseRequest = idpConnector.buildSaml20SingleLogoutResponse(
				binding, originRequestId);

		this.sendSloResponse(binding, sloResponseRequest);

		this.logger.debug("SAML 2.0 Logout Response processing ended.");
		return null;
	}

	/**
	 * Process a SLO Response.
	 * 
	 * @param request the HTTP request
	 * @param binding the SLO Response binding
	 * @param idpConnector
	 * @return the SLO Response
	 * @throws SamlProcessingException
	 * @throws NotSignedException
	 * @throws ValidationException
	 */
	protected SamlResponseData processSaml20SingleLogoutResponse(final LogoutResponse logoutResponse,
			final SamlBindingEnum binding, final ISaml20IdpConnector idpConnector) throws SamlProcessingException, ValidationException, NotSignedException {
		Assert.notNull(logoutResponse, "SLO Response must be supplied !");
		this.logger.debug("Processing a SAML 2.0 Single Logout Response...");

		SamlResponseData samlResponseData = new SamlResponseData();

		this.validateResponseSignatureTrust(logoutResponse, idpConnector);

		// Logging XML Authn Response
		try {
			String messageXML = OpenSamlHelper.marshallXmlObject(logoutResponse);

			samlResponseData.setSamlResponse(messageXML);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(String.format("SAML Logout Response: %s", messageXML));
			}
		} catch (MarshallingException e) {
			this.logger.warn("Error while marshalling SAML 2.0 Logout Response !", e);
		}

		String samlId = logoutResponse.getID();
		samlResponseData.setId(samlId);
		samlResponseData.setInResponseToId(logoutResponse.getInResponseTo());

		// No need to store a SLO Response request !
		// this.storeSamlResponseDataInCache(samlResponseData);

		this.logger.debug("SAML 2.0 Logout Response processing ended.");
		return samlResponseData;
	}

	/**
	 * Send the SLO Response via the URL Api.
	 * 
	 * @param binding the binding to use
	 * @param sloResponseRequest the SLO Response request
	 */
	protected void sendSloResponse(final SamlBindingEnum binding, final SamlRequestData sloResponseRequest) {
		URL sloUrl = null;
		HttpURLConnection sloConnexion = null;

		try {
			switch(binding) {
			case SAML_20_HTTP_REDIRECT:
				String redirectUrl = sloResponseRequest.buildSamlHttpRedirectRequestUrl();

				sloUrl = new URL(redirectUrl);
				sloConnexion = (HttpURLConnection) sloUrl.openConnection();
				sloConnexion.setReadTimeout(10000);
				sloConnexion.connect();
				break;

			case SAML_20_HTTP_POST:
				String sloEndpointUrl = sloResponseRequest.getEndpointUrl();

				StringBuffer samlDatas = new StringBuffer(1024);
				samlDatas.append("RelayState=");
				samlDatas.append(sloResponseRequest.getRelayState());
				samlDatas.append("&SAMLRequest=");
				samlDatas.append(sloResponseRequest.getSamlRequest());

				sloUrl = new URL(sloEndpointUrl);
				sloConnexion = (HttpURLConnection) sloUrl.openConnection();
				sloConnexion.setDoInput(true);

				OutputStreamWriter writer = new OutputStreamWriter(sloConnexion.getOutputStream());
				writer.write(samlDatas.toString());
				writer.flush();
				writer.close();

				sloConnexion.setReadTimeout(10000);
				sloConnexion.connect();
				break;

			default:
				break;
			}

			if (sloConnexion != null) {
				InputStream responseStream = sloConnexion.getInputStream();

				StringWriter writer = new StringWriter();
				IOUtils.copy(responseStream, writer, "UTF-8");
				String response = writer.toString();

				this.logger.debug(String.format("HTTP response to SLO Request sent: [%s] ", response));

				int responseCode = sloConnexion.getResponseCode();

				String samlResponse = sloResponseRequest.getSamlRequest();
				String entityId = sloResponseRequest.getIdpConnectorBuilder().getIdpConfig().getIdpEntityId();
				if (responseCode < 0) {
					this.logger.error(String.format("Unable to send SAML 2.0 Single Logout Response [%s] to IdP [%s] !",
							samlResponse, entityId));
				} else if (responseCode == 200) {
					this.logger.info(String.format("SAML 2.0 Single Logout Request correctly received by IdP [%s] !",
							sloResponseRequest.getIdpConnectorBuilder().getIdpConfig().getIdpEntityId()));
				} else {
					this.logger.error(String.format(
							"HTTP response code: [%s] ! Error while sending SAML 2.0 Single Logout Request [%s] to IdP [%s] !",
							samlResponse, entityId));
				}
			}

		} catch (MalformedURLException e) {
			this.logger.error(String.format("Malformed SAML SLO request URL: [%s] !",
					sloUrl.toExternalForm()), e);
		} catch (IOException e) {
			this.logger.error(String.format("Unable to send SAML SLO request URL: [%s] !",
					sloUrl.toExternalForm()), e);
		} finally {
			sloConnexion.disconnect();
		}
	}

	/**
	 * Logout from CAS.
	 * 
	 * @param nameID
	 */
	private void logoutFromCas(final NameID nameID) {
		if (nameID != null) {
			String tgtId = this.samlFacade.findTgtIdBySamlNameId(nameID.getValue());

			this.cas.destroyTicketGrantingTicket(tgtId);

			this.samlFacade.removeAuthenticationInfosFromCache(tgtId);
		}
	}

	/**
	 * Build the SAML message context from a HttpServletRequest.
	 * 
	 * @param request
	 *            the HttpServletRequest
	 * @param binding
	 * @return the SAML message context
	 * @throws SecurityException
	 *             in case of Security problem
	 * @throws MessageDecodingException
	 *             in case of decoding problem
	 */
	@SuppressWarnings("rawtypes")
	protected MessageContext buildMessageContext(final HttpServletRequest request, final SamlBindingEnum binding)
			throws SecurityException, MessageDecodingException {
		Validate.notNull(request, "Request must be supplied !");

		MessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setInboundMessageTransport(new HttpServletRequestAdapter(request));

		try {
			this.getSamlMessageDecoder(binding).decode(messageContext);
		} catch (SecurityException e) {
			// Security problem !
			this.logger.warn("Security error while decoding SAML Message !", e);
		}

		this.validateMessageContext(messageContext);

		return messageContext;
	}

	/**
	 * Validate the message context if MessageReplayRule was provided.
	 * 
	 * @param messageContext
	 *            the message context
	 * @throws SecurityPolicyException
	 *             in case of rule requirements problem.
	 */
	protected void validateMessageContext(final MessageContext messageContext) throws SecurityPolicyException {
		if ((this.rule != null) && (messageContext != null)) {
			this.rule.evaluate(messageContext);
		}
	}

	/**
	 * Extract SAML Object from request.
	 * @param binding
	 * 
	 * @param messageContext
	 *            the message context
	 * @return the SAML Authn Response. It can't be null !
	 * @throws ValidationException
	 *             in case of validation problem
	 * @throws SecurityException
	 * @throws MessageDecodingException
	 */
	protected SAMLObject extractSamlObjectFromRequest(final HttpServletRequest request, final SamlBindingEnum binding)
			throws ValidationException, MessageDecodingException, SecurityException {
		SAMLObject samlObject = null;

		MessageContext messageContext = this.buildMessageContext(request, binding);

		Validate.notNull(messageContext, "MessageContext must be supplied !");

		XMLObject inboundMessage = messageContext.getInboundMessage();
		if ((inboundMessage != null) && SAMLObject.class.isAssignableFrom(inboundMessage.getClass())) {
			samlObject = (SAMLObject) inboundMessage;
		} else {
			throw new ValidationException("Unable to find a SAML Object in HTTP request !");
		}

		return samlObject;
	}

	/**
	 * Retrieve the first normal assertion.
	 * 
	 * @param samlResponse
	 *            the saml response containing the assertions.
	 * @return the first normal assertion. It can be null !
	 */
	protected Assertion retieveFirstAssertion(final Response samlResponse) {
		Validate.notNull(samlResponse, "Response must be supplied !");

		List<Assertion> assertions = samlResponse.getAssertions();
		Assertion assertion = null;
		if (assertions != null) {
			assertion = assertions.iterator().next();
		}

		return assertion;
	}

	/**
	 * Retrieve the first encrypted assertion.
	 * 
	 * @param samlResponse
	 *            the saml response containing the assertions.
	 * @param decrypter
	 * @return the first encrypted assertion. It can be null !
	 * @throws DecryptionException
	 *             in case of decryption problem.
	 */
	protected Assertion retieveFirstEncryptedAssertion(final Response samlResponse, final Decrypter decrypter) throws DecryptionException {
		Validate.notNull(samlResponse, "Response must be supplied !");

		List<EncryptedAssertion> encAssertions = samlResponse.getEncryptedAssertions();
		EncryptedAssertion encAssertion = null;
		Assertion assertion = null;

		if (!CollectionUtils.isEmpty(encAssertions)) {
			encAssertion = encAssertions.iterator().next();
		}

		if ((encAssertion != null) && (decrypter != null)) {
			assertion = decrypter.decrypt(encAssertion);
		}

		return assertion;
	}

	/**
	 * Retrieve all assertions, normal ones and encrypted ones if a private kay
	 * was provided.
	 * 
	 * @param samlResponse
	 *            the saml response containing the assertions.
	 * @return the list of all assertions.
	 * @throws DecryptionException
	 *             in case of decryption problem.
	 */
	protected List<Assertion> retrieveAllAssertions(final Response samlResponse, final Decrypter decrypter) throws DecryptionException {
		List<Assertion> allAssertions = new ArrayList<Assertion>();
		if (samlResponse != null) {
			List<Assertion> normalAssertions = samlResponse.getAssertions();
			if (!CollectionUtils.isEmpty(normalAssertions)) {
				allAssertions.addAll(normalAssertions);
			}

			List<EncryptedAssertion> encAssertions = samlResponse.getEncryptedAssertions();
			if ((decrypter != null) && (!CollectionUtils.isEmpty(encAssertions))) {
				for (EncryptedAssertion encAssertion : samlResponse.getEncryptedAssertions()) {
					Assertion assertion = decrypter.decrypt(encAssertion);
					allAssertions.add(assertion);
				}
			}
		}

		return allAssertions;
	}

	/**
	 * Add each assertion attributes and its values in an attributes map.
	 * 
	 * @param assertion the assertion
	 * @param attributesMap the map to put attributes into
	 */
	protected void processAssertionAttributes(final Assertion assertion, final Map<String, List<String>> attributesMap) {
		List<Attribute> attributes = this.retrieveAttributes(assertion);
		if (!CollectionUtils.isEmpty(attributes)) {
			for (Attribute attr : attributes) {
				if (attr != null) {
					List<String> values = new ArrayList<String>();
					for (XMLObject value : attr.getAttributeValues()) {
						if (value != null) {
							String textContent = value.getDOM().getTextContent();
							if (StringUtils.hasText(textContent)) {
								values.add(textContent);
							}
						}
					}
					if (!CollectionUtils.isEmpty(values)) {
						attributesMap.put(attr.getFriendlyName(), values);
					}
				}
			}
		}
	}

	/**
	 * Validate the Saml2 response signature if a signature profile validator was provided.
	 * Verify the Saml2 response signature with IdP Metadata.
	 * 
	 * @param response the Saml 2.0 Response to validate and verify.
	 * @throws ValidationException
	 * @throws NotSignedException if no signature present
	 */
	protected void validateAssertionSignatureTrust(final Assertion assertion,
			final ISaml20IdpConnector idpConnector)
					throws ValidationException, NotSignedException {
		if (assertion != null) {

			CriteriaSet criteriaSet = new CriteriaSet();
			criteriaSet.add(new EntityIDCriteria(assertion.getIssuer().getValue()) );

			this.validateSignatureTrust(assertion, criteriaSet, idpConnector);
		}
	}

	/**
	 * Validate the Saml2 response signature if a signature profile validator was provided.
	 * Verify the Saml2 response signature with IdP Metadata.
	 * 
	 * @param response an Saml 2.0 Response to validate and verify.
	 * @throws ValidationException
	 * @throws NotSignedException if the response isn't signed
	 */
	protected void validateResponseSignatureTrust(final StatusResponseType response,
			final ISaml20IdpConnector idpConnector) throws ValidationException, NotSignedException {
		if (response != null) {

			CriteriaSet criteriaSet = new CriteriaSet();
			criteriaSet.add(new EntityIDCriteria(response.getIssuer().getValue()) );

			this.validateSignatureTrust(response, criteriaSet, idpConnector);
		}
	}

	/**
	 * Validate a Saml2 signature if a signature profile validator was provided.
	 * Verify a Saml2 signature with IdP Metadata.
	 * 
	 * @param response the Saml 2.0 Response to validate and verify.
	 * @throws ValidationException
	 * @throws NotSignedException if no signature present
	 */
	protected void validateSignatureTrust(final SignableSAMLObject signableObject, final CriteriaSet criteriaSet,
			final ISaml20IdpConnector idpConnector) throws ValidationException, NotSignedException {
		if (signableObject != null) {
			Signature signature = signableObject.getSignature();
			if ((signature == null) || signature.isNil()) {
				throw new NotSignedException("The signature is missing !");
			}

			if (this.signatureProfileValidator != null) {
				this.signatureProfileValidator.validate(signature);
			}

			// On test mode only if security keys are provided
			criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME, SAMLConstants.SAML20P_NS));
			criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

			try {
				SignatureTrustEngine signatureTrustEngine = idpConnector.getIdpConfig().getSignatureTrustEngine();
				if (!signatureTrustEngine.validate(signature, criteriaSet)) {
					throw new ValidationException("Signature was either invalid or signing key could not be established as trusted !");
				}
			} catch (SecurityException e) {
				throw new ValidationException("Error while validating the security token !", e);
			}

		}

	}

	/**
	 * Validate an assertion subject.
	 * 
	 * @param assertion
	 *            the assertion containing the subject
	 * @return the validated subject. It can be null !
	 * @throws ValidationException
	 *             in case of validation problem
	 */
	protected Subject validateAndRetrieveSubject(final Assertion assertion) throws ValidationException {
		Subject subject = null;
		if (assertion != null) {
			subject = assertion.getSubject();
			List<SubjectConfirmation> subjectConfirmations = null;

			SubjectConfirmationData scData = null;

			if (subject != null) {
				subjectConfirmations = subject.getSubjectConfirmations();
			}

			if (!CollectionUtils.isEmpty(subjectConfirmations)) {
				for (SubjectConfirmation subjectConfirmation : subjectConfirmations) {
					if (subjectConfirmation != null) {
						scData = subjectConfirmation.getSubjectConfirmationData();
						this.validateTimes(scData.getNotBefore(), scData.getNotOnOrAfter());
					}
				}
			}

			@SuppressWarnings("unused")
			NameID nameId = subject.getNameID();

		}
		return subject;
	}

	/**
	 * Retrieve the session index for an assertion.
	 * 
	 * @param assertionsession index
	 */
	protected String retrieveSessionIndex(final Assertion assertion) {
		String sessionIndex = null;

		if (assertion != null) {
			List<AuthnStatement> authnStatments = assertion.getAuthnStatements();

			for (AuthnStatement authnStatment : authnStatments) {
				sessionIndex = authnStatment.getSessionIndex();
				if (StringUtils.hasText(sessionIndex)) {
					break;
				}

			}
		}

		return sessionIndex;
	}

	/**
	 * Retrieve assertion attributes.
	 * 
	 * @param assertion
	 *            the assertion containing the attributes
	 * @return the list of all attributes.
	 */
	protected List<Attribute> retrieveAttributes(final Assertion assertion) {
		List<Attribute> attributes = new ArrayList<Attribute>();

		if (assertion != null) {
			List<AttributeStatement> statements = assertion.getAttributeStatements();
			if (!CollectionUtils.isEmpty(statements)) {
				for (AttributeStatement statement : statements) {
					List<Attribute> attrs = statement.getAttributes();
					if (!CollectionUtils.isEmpty(attrs)) {
						attributes.addAll(attrs);
					}
				}
			}
		}

		this.logger.debug(String.format("%s attribute(s) found in SAML assertion.", attributes.size()));

		return attributes;
	}

	/**
	 * Validate assertion conditions.
	 * 
	 * @param assertion
	 *            the assertion to validate
	 * @throws ValidationException
	 *             in case of validation problem
	 */
	protected void validateConditions(final Assertion assertion) throws ValidationException {
		if (assertion != null) {
			Conditions conditions = assertion.getConditions();
			this.validateTimes(conditions.getNotBefore(), conditions.getNotOnOrAfter());
		}
	}

	/**
	 * Validate times notBefore and notOnOrAfter conditions.
	 * 
	 * @param notBefore
	 *            notBefore condition
	 * @param notOnOrAfter
	 *            notOnOrAfter condition
	 * @throws ValidationException
	 *             in case of validation problem.
	 */
	protected void validateTimes(final DateTime notBefore, final DateTime notOnOrAfter) throws ValidationException {
		Instant serverInstant = new Instant();

		if (notBefore != null) {
			// Instant with skew
			Instant notBeforeInstant = notBefore.toInstant().withDurationAdded(this.clockSkewSeconds * 1000, -1);

			if (serverInstant.isBefore(notBeforeInstant)) {
				throw new ValidationException("SAML 2.0 Message is outdated (too early) !");
			}
		}

		if ((notOnOrAfter != null)) {
			// Instant with skew
			Instant notOrOnAfterInstant = notOnOrAfter.toInstant().withDurationAdded(
					(this.clockSkewSeconds * 1000) - 1, 1);

			if (serverInstant.isAfter(notOrOnAfterInstant)) {
				throw new ValidationException("SAML 2.0 Message is outdated (too late) !");
			}
		}

	}

	/**
	 * Retrieve the SAML message decoder attached to the binding.
	 * 
	 * @param binding the binding
	 * @return the right SAML message decoder
	 */
	protected SAMLMessageDecoder getSamlMessageDecoder(final SamlBindingEnum binding) {
		return this.samlMessageDecoders.get(binding);
	}

	/**
	 * Initialize caches if needed.
	 * 
	 * @throws IOException
	 * @throws CacheException
	 */
	protected void initCaches() throws CacheException, IOException {
		if (this.samlRequestDataCache == null) {
			EhCacheFactoryBean requestCacheFactory = new EhCacheFactoryBean();
			String requestCacheName = OpenSaml20SpProcessor.SAML2_REQUEST_DATA_CACHE_NAME;
			requestCacheFactory.setCacheName(requestCacheName);
			requestCacheFactory.afterPropertiesSet();
			this.samlRequestDataCache = requestCacheFactory.getObject();
		}

		if (this.samlResponseDataCache == null) {
			EhCacheFactoryBean responseCacheFactory = new EhCacheFactoryBean();
			String responseCacheName = OpenSaml20SpProcessor.SAML2_RESPONSE_DATA_CACHE_NAME;
			responseCacheFactory.setCacheName(responseCacheName);
			responseCacheFactory.afterPropertiesSet();
			this.samlResponseDataCache = responseCacheFactory.getObject();
		}

		this.samlRequestDataCache.bootstrap();
		this.samlResponseDataCache.bootstrap();
	}

	public void setSpConfig(final ISpConfig spConfig) {
		this.spConfig = spConfig;
	}

	/**
	 * Build a decrypter if a private key was provided.
	 * 
	 * @return the decrypter
	 */
	protected Decrypter buildDecrypter() {
		Decrypter decrypter = null;

		BasicCredential credential = new BasicCredential();
		credential.setPrivateKey(this.getSpConfig().getDecryptionKey());
		decrypter = new Decrypter(null, new StaticKeyInfoCredentialResolver(credential),
				new InlineEncryptedKeyResolver());

		return decrypter;
	}

	/**
	 * Build a SAML2 signature with signing credentials.
	 * 
	 * @return the SAML2 signature.
	 */
	protected Signature buildSignature() {
		Signature signature = this.signatureBuilder.buildObject();

		try {
			SecurityHelper.prepareSignatureParams(signature, this.spSigningCredential, Configuration.getGlobalSecurityConfiguration(), null);
			signature.setSigningCredential(this.spSigningCredential);

			// FIX MBD: Remove key info which is optional to save request length
			signature.setKeyInfo(null);

		} catch (SecurityException e) {
			this.logger.error("Error while building signature !", e);
			signature = null;
		}

		return signature;
	}

	public Map<SamlBindingEnum, SAMLMessageDecoder> getSamlMessageDecoders() {
		return this.samlMessageDecoders;
	}

	public void setSamlMessageDecoders(final Map<SamlBindingEnum, SAMLMessageDecoder> samlMessageDecoders) {
		this.samlMessageDecoders = samlMessageDecoders;
	}

	public SAMLSignatureProfileValidator getSignatureProfileValidator() {
		return this.signatureProfileValidator;
	}

	public void setSignatureProfileValidator(final SAMLSignatureProfileValidator signatureProfileValidator) {
		this.signatureProfileValidator = signatureProfileValidator;
	}

	public MessageReplayRule getRule() {
		return this.rule;
	}

	public void setRule(final MessageReplayRule rule) {
		this.rule = rule;
	}

	public int getReplayMinutes() {
		return this.replayMinutes;
	}

	public void setReplayMinutes(final int replayMinutes) {
		this.replayMinutes = replayMinutes;
	}

	public int getClockSkewSeconds() {
		return this.clockSkewSeconds;
	}

	public void setClockSkewSeconds(final int clockSkewSeconds) {
		this.clockSkewSeconds = clockSkewSeconds;
	}

	public Ehcache getSamlRequestDataCache() {
		return this.samlRequestDataCache;
	}

	public void setSamlRequestDataCache(final Ehcache samlRequestDataCache) {
		this.samlRequestDataCache = samlRequestDataCache;
	}

	public Ehcache getSamlResponseDataCache() {
		return this.samlResponseDataCache;
	}

	public void setSamlResponseDataCache(final Ehcache samlResponseDataCache) {
		this.samlResponseDataCache = samlResponseDataCache;
	}

	public Collection<ISaml20IdpConnector> getIdpConnectors() {
		return this.idpConnectors;
	}

	public void setIdpConnectors(final Collection<ISaml20IdpConnector> idpConnectors) {
		this.idpConnectors = idpConnectors;
	}

	public ISaml20Facade getSamlFacade() {
		return this.samlFacade;
	}

	public void setSamlFacade(final ISaml20Facade samlFacade) {
		this.samlFacade = samlFacade;
	}

	public CentralAuthenticationService getCas() {
		return this.cas;
	}

	public void setCas(final CentralAuthenticationService cas) {
		this.cas = cas;
	}

}
