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

import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import net.sf.ehcache.CacheException;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.esco.cas.ISaml20Facade;
import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.ISpConfig;
import org.esco.sso.security.saml.ISaml20IdpConnector;
import org.esco.sso.security.saml.ISaml20SpProcessor;
import org.esco.sso.security.saml.exception.SamlProcessingException;
import org.esco.sso.security.saml.exception.SamlSecurityException;
import org.esco.sso.security.saml.exception.UnsupportedSamlOperation;
import org.esco.sso.security.saml.om.IAuthentication;
import org.esco.sso.security.saml.om.IIncomingSaml;
import org.esco.sso.security.saml.om.IRequestWaitingForResponse;
import org.esco.sso.security.saml.query.IQueryProcessor;
import org.esco.sso.security.saml.query.IQueryProcessorFactory;
import org.esco.sso.security.saml.util.SamlHelper;
import org.jasig.cas.CentralAuthenticationService;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.StatusResponseType;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.SignatureBuilder;
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

	/** SAML 2.0 Request waiting for response cache name. */
	private static final String SAML2_RWFR_CACHE_NAME = "samlRequestWaitingForResponseCache";

	/** SAML 2.0 Authentications cache name. */
	private static final String SAML2_AUTHN_CACHE_NAME = "samlAuthenticationCache";

	/** SP Configuration. */
	private ISpConfig spConfig;

	/** Decrypt responses encrypted assertions with spCertificate. */
	private Decrypter decrypter;

	/** Signature builder. */
	private SignatureBuilder signatureBuilder = new SignatureBuilder();

	/** SP Signing credentials (spSigningKey + spSigningCertificate). */
	private Credential spSigningCredential;

	/** Cache for Request which wait for a response to be received. */
	private Ehcache samlRequestWaitingForResponseCache;

	/** Cache for SAML authentications already processed. */
	private Ehcache samlAuthenticationsCache;

	/** IdP connectors. */
	private Collection<ISaml20IdpConnector> idpConnectors;

	/** Map of IdP connectors indexed by their entity Id. */
	private Map<String, ISaml20IdpConnector> idpConnectorsByEntityId = new HashMap<String, ISaml20IdpConnector>();

	/** SAML 2.0 Facade. */
	private ISaml20Facade samlFacade;

	/** CAS service. */
	private CentralAuthenticationService cas;

	/** Query Processor Factory. */
	private IQueryProcessorFactory queryProcessorFactory;

	@Override
	public IIncomingSaml processSaml20IncomingRequest(final HttpServletRequest request) throws SamlProcessingException,
			UnsupportedSamlOperation {
		IIncomingSaml incomingSaml = null;

		// Build the adapted query processor
		IQueryProcessor queryProcessor = this.queryProcessorFactory.buildQueryProcessor(this, request);

		// Process the message
		incomingSaml = queryProcessor.processIncomingSamlMessage();

		return incomingSaml;
	}

	@Override
	public ISaml20IdpConnector findSaml20IdpConnectorToUse(final String idpEntityId) {
		return this.idpConnectorsByEntityId.get(idpEntityId);
	}

	@Override
	public IRequestWaitingForResponse retrieveRequestWaitingForResponse(final String inResponseToId) {
		IRequestWaitingForResponse result = null;

		Assert.hasText(inResponseToId, "No inResponseToId provided !");
		final Element element = this.samlRequestWaitingForResponseCache.get(inResponseToId);
		if (element != null) {
			result = (IRequestWaitingForResponse) element.getValue();
		}

		return result;
	}

	@Override
	public void storeRequestWaitingForResponseInCache(final IRequestWaitingForResponse requestData) {
		Assert.notNull(requestData, "Trying to store a null request in cache !");
		Assert.hasText(requestData.getId(), "Trying to store a request without Id in cache !");
		this.samlRequestWaitingForResponseCache.put(new Element(requestData.getId(), requestData));
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
		Signature newSignature = this.buildSignature(true);

		signable.setSignature(newSignature);
		return newSignature;
	}

	@Override
	public boolean logout(final String sessionIndex) {
		this.logoutFromCas(sessionIndex);
		return true;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.samlFacade, "The SAML 2.0 Facade wasn't injected !");
		Assert.notNull(this.cas, "The CAS service wasn't injected !");
		Assert.notNull(this.getSpConfig(), "No SP configuration provided for this SP processor !");
		Assert.notNull(this.queryProcessorFactory, "No QueryProcessorFactory injected !");

		// Retrieve IdP connectors and
		// Register this SP processor in the IdP connectors
		Assert.notEmpty(this.idpConnectors, "No IdP connector injected in the SP processor !");
		for (ISaml20IdpConnector idpConnector : this.idpConnectors) {
			try {
				idpConnector.registerSaml20SpProcessor(this);
				final IIdpConfig idpConfig = idpConnector.getIdpConfig();
				if (idpConfig != null) {
					this.idpConnectorsByEntityId.put(idpConfig.getIdpEntityId(), idpConnector);
				} else {
					this.logger.warn(
							"No IdP config found while registering an IdPConnector in SPProcessor with id: [{}] !",
							this.getSpConfig().getId());
				}
			} catch (IllegalAccessError e) {
				// Catch exception thrown by fake IdPs like CAS Fake IdP.
			}
		}

		this.spSigningCredential = SecurityHelper.getSimpleCredential(this.getSpConfig().getSigningCredential()
				.getEntityCertificate(), this.getSpConfig().getSigningKey());
		Assert.notNull(this.spSigningCredential,
				"Unable to build SP signing credentials (signing public + private keys) !");

		this.decrypter = this.buildDecrypter();

		this.initCaches();

		// Register this processor in the Helper
		SamlHelper.registerSpProcessor(this);
	}

	/**
	 * Check if the Response correspond to a request already present in request cache !
	 * Remove the Request Data from request cache.
	 *
	 * @param response
	 * @return the original request cannot be null
	 * @throws SamlSecurityException
	 */
	protected IRequestWaitingForResponse checkInResponseToRequest(final String inResponseToId)
			throws SamlSecurityException {
		IRequestWaitingForResponse request = null;

		if (StringUtils.hasText(inResponseToId)) {
			// Get request from cache
			Element element = this.samlRequestWaitingForResponseCache.get(inResponseToId);
			if (element != null) {
				request = (IRequestWaitingForResponse) element.getObjectValue();

				// Clear request from cache
				this.samlRequestWaitingForResponseCache.remove(inResponseToId);
			}
		}

		if (request == null) {
			throw new SamlSecurityException("Response reference a Request which is not (anymore ?) in cache !");
		}

		return request;
	}

	/** Clear caches. Use it for test purpose only ! */
	public void clearCaches() {
		this.samlRequestWaitingForResponseCache.removeAll();
		this.samlAuthenticationsCache.removeAll();
	}

	/**
	 * Store a SAML Authentication in the cache by the IdP session index.
	 *
	 * @param authns the collection of authentications
	 * @throws SamlSecurityException
	 */
	protected void storeSamlAuthenticationsInCache(final List<IAuthentication> authns) throws SamlSecurityException {
		if (!CollectionUtils.isEmpty(authns)) {
			for (IAuthentication auth : authns) {
				String authKey = auth.getSessionIndex();
				// Check auth already done
				final Element alreadyAuthenticated = this.samlAuthenticationsCache.get(authKey);
				if (alreadyAuthenticated != null) {
					throw new SamlSecurityException("Attempt to replay a previous authentication !");
				}

				final Element element = new Element(authKey, auth);
				this.samlAuthenticationsCache.put(element);
			}
		}
	}

	/**
	 * Find a chached Saml Authentication.
	 *
	 * @param sessionId
	 * @return
	 */
	protected IAuthentication getCachedSamlAuthentications(final String sessionIndex) {
		IAuthentication result = null;

		if (StringUtils.hasText(sessionIndex)) {
			final Element element = this.samlAuthenticationsCache.get(sessionIndex);
			if (element != null) {
				result = (IAuthentication) element.getObjectValue();
			}
		}

		return result;
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
				Element element = this.samlRequestWaitingForResponseCache.get(originalRequestId);
				if (element != null) {
					Object value = element.getValue();
					if (value != null) {
						IRequestWaitingForResponse originalRequestData = (IRequestWaitingForResponse) element
								.getValue();
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
			throw new SamlProcessingException("Unable to find an IdP Connector to process the SAML request !");
		}

		return samlConnector;
	}

	/**
	 * Logout from CAS.
	 *
	 * @param nameID
	 */
	protected void logoutFromCas(final String sessionIndex) {
		if (StringUtils.hasText(sessionIndex)) {
			String tgtId = this.samlFacade.findTgtIdBySamlNameId(sessionIndex);

			this.cas.destroyTicketGrantingTicket(tgtId);

			this.samlFacade.removeAuthenticationInfosFromCache(tgtId);
		}
	}

	/**
	 * Initialize caches if needed.
	 *
	 * @throws IOException
	 * @throws CacheException
	 */
	protected void initCaches() throws CacheException, IOException {
		if (this.samlRequestWaitingForResponseCache == null) {
			EhCacheFactoryBean requestCacheFactory = new EhCacheFactoryBean();
			String requestCacheName = OpenSaml20SpProcessor.SAML2_RWFR_CACHE_NAME;
			requestCacheFactory.setCacheName(requestCacheName);
			requestCacheFactory.afterPropertiesSet();
			this.samlRequestWaitingForResponseCache = requestCacheFactory.getObject();
		}

		if (this.samlAuthenticationsCache == null) {
			EhCacheFactoryBean responseCacheFactory = new EhCacheFactoryBean();
			String responseCacheName = OpenSaml20SpProcessor.SAML2_AUTHN_CACHE_NAME;
			responseCacheFactory.setCacheName(responseCacheName);
			responseCacheFactory.afterPropertiesSet();
			this.samlAuthenticationsCache = responseCacheFactory.getObject();
		}

		this.samlRequestWaitingForResponseCache.bootstrap();
		this.samlAuthenticationsCache.bootstrap();
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
	protected Signature buildSignature(final boolean withoutKeyInfo) {
		Signature signature = this.signatureBuilder.buildObject();

		try {
			SecurityHelper.prepareSignatureParams(signature, this.spSigningCredential,
					Configuration.getGlobalSecurityConfiguration(), null);
			signature.setSigningCredential(this.spSigningCredential);

			// FIX MBD: Remove key info which is optional to save request length
			if (withoutKeyInfo) {
				signature.setKeyInfo(null);
			}

		} catch (SecurityException e) {
			this.logger.error("Error while building signature !", e);
			signature = null;
		}

		return signature;
	}

	public Ehcache getSamlRequestDataCache() {
		return this.samlRequestWaitingForResponseCache;
	}

	public void setSamlRequestDataCache(final Ehcache samlRequestDataCache) {
		this.samlRequestWaitingForResponseCache = samlRequestDataCache;
	}

	public Ehcache getSamlResponseDataCache() {
		return this.samlAuthenticationsCache;
	}

	public void setSamlResponseDataCache(final Ehcache samlResponseDataCache) {
		this.samlAuthenticationsCache = samlResponseDataCache;
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

	public IQueryProcessorFactory getQueryProcessorFactory() {
		return this.queryProcessorFactory;
	}

	public void setQueryProcessorFactory(final IQueryProcessorFactory queryProcessorFactory) {
		this.queryProcessorFactory = queryProcessorFactory;
	}

}
