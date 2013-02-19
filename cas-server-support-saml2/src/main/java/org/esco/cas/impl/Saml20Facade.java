/**
 * 
 */
package org.esco.cas.impl;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import net.sf.ehcache.CacheException;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;

import org.esco.cas.ISaml20Facade;
import org.jasig.cas.web.support.CookieRetrievingCookieGenerator;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.cache.ehcache.EhCacheFactoryBean;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Facade for CAS SAML 2.0 usage
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class Saml20Facade implements ISaml20Facade, InitializingBean {

	/** SAML 2.0 Authentication credentials cache name. */
	public static final String SAML2_AUTH_CREDS_CACHE_NAME = "saml2AuthCredsCache";

	/** SAML 2.0 Authentication Base ID cache name. */
	private static final String SAML2_BASE_ID_CACHE_NAME = "saml2BaseIdCache";

	/** SAML 2.0 Authentication Name ID cache name. */
	private static final String SAML2_NAME_ID_CACHE_NAME = "saml2NameIdCache";

	/** SAML 2.0 Authentication credentials cache. */
	private Ehcache saml2AuthenticatedCredentialsCache;

	/** SAML 2.0 Authentication Name ID cache. */
	private Ehcache saml2NameIdCache;

	/** SAML 2.0 Authentication Base ID cache. */
	private Ehcache saml2BaseIdCache;

	/** CookieGenerator for the TicketGrantingTickets. */
	private CookieRetrievingCookieGenerator tgtCookieGenerator;

	@Override
	public void storeAuthenticationInfosInCache(final String tgtId, final SamlAuthInfo authInfos) {
		if (StringUtils.hasText(tgtId) && (authInfos != null)) {
			if (this.saml2AuthenticatedCredentialsCache.isKeyInCache(tgtId)) {
				// TGT already used !
				throw new IllegalStateException(String.format(
						"Unable to store SAML 2.0 authenticated credentials in cache beacause TGT [%s] is already present !", tgtId));
			}
			this.saml2AuthenticatedCredentialsCache.put(new Element(tgtId, authInfos));

			String idpSubject = authInfos.getIdpSubject();
			if (StringUtils.hasText(idpSubject)) {
				this.saml2NameIdCache.put(new Element(idpSubject, tgtId));
			}
		}
	}

	@Override
	public SamlAuthInfo retrieveAuthenticationInfosFromCache(final String tgtId) {
		SamlAuthInfo authInfos = null;

		if (StringUtils.hasText(tgtId)) {
			Element element = this.saml2AuthenticatedCredentialsCache.get(tgtId);
			if (element != null) {
				Object value = element.getValue();
				if (value != null) {
					authInfos = (SamlAuthInfo) value;
				}
			}
		}

		return authInfos;
	}

	@Override
	public SamlAuthInfo removeAuthenticationInfosFromCache(final String tgtId) {
		SamlAuthInfo authInfos = this.retrieveAuthenticationInfosFromCache(tgtId);

		if (StringUtils.hasText(tgtId)) {
			this.saml2AuthenticatedCredentialsCache.remove(tgtId);
		}

		if (authInfos != null) {
			String idpSubject = authInfos.getIdpSubject();
			if (StringUtils.hasText(idpSubject)) {
				this.saml2NameIdCache.remove(idpSubject);
			}
		}

		return authInfos;
	}

	@Override
	public String retrieveTgtIdFromCookie(final HttpServletRequest request) {
		String tgtId = null;

		if (request != null) {
			tgtId = this.tgtCookieGenerator.retrieveCookieValue(request);
		}

		return tgtId;
	}

	/**
	 * Initialize caches if needed.
	 * 
	 * @throws IOException
	 * @throws CacheException
	 */
	protected void initCache() throws CacheException, IOException {
		if (this.saml2AuthenticatedCredentialsCache == null) {
			EhCacheFactoryBean cacheFactory = new EhCacheFactoryBean();
			cacheFactory.setCacheName(Saml20Facade.SAML2_AUTH_CREDS_CACHE_NAME);
			cacheFactory.afterPropertiesSet();
			this.saml2AuthenticatedCredentialsCache = cacheFactory.getObject();
		}
		this.saml2AuthenticatedCredentialsCache.bootstrap();

		if (this.saml2BaseIdCache == null) {
			EhCacheFactoryBean cacheFactory = new EhCacheFactoryBean();
			cacheFactory.setCacheName(Saml20Facade.SAML2_BASE_ID_CACHE_NAME);
			cacheFactory.afterPropertiesSet();
			this.saml2BaseIdCache = cacheFactory.getObject();
		}
		this.saml2BaseIdCache.bootstrap();

		if (this.saml2NameIdCache == null) {
			EhCacheFactoryBean cacheFactory = new EhCacheFactoryBean();
			cacheFactory.setCacheName(Saml20Facade.SAML2_NAME_ID_CACHE_NAME);
			cacheFactory.afterPropertiesSet();
			this.saml2NameIdCache = cacheFactory.getObject();
		}
		this.saml2NameIdCache.bootstrap();
	}

	@Override
	public String findTgtIdBySamlNameId(final String nameId) {
		String tgtId = null;

		if (StringUtils.hasText(nameId)) {
			Element element = this.saml2NameIdCache.get(nameId);
			if (element != null) {
				tgtId = (String) element.getValue();
			}
		}

		return tgtId;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.tgtCookieGenerator, "The CAS TGT cookie generator wasn't injected !");

		this.initCache();
	}

	public Ehcache getSaml2AuthenticatedCredentialsCache() {
		return this.saml2AuthenticatedCredentialsCache;
	}

	public void setSaml2AuthenticatedCredentialsCache(final Ehcache saml2AuthenticatedCredentialsCache) {
		this.saml2AuthenticatedCredentialsCache = saml2AuthenticatedCredentialsCache;
	}

	public Ehcache getSaml2NameIdCache() {
		return this.saml2NameIdCache;
	}

	public void setSaml2NameIdCache(final Ehcache saml2NameIdCache) {
		this.saml2NameIdCache = saml2NameIdCache;
	}

	public Ehcache getSaml2BaseIdCache() {
		return this.saml2BaseIdCache;
	}

	public void setSaml2BaseIdCache(final Ehcache saml2BaseIdCache) {
		this.saml2BaseIdCache = saml2BaseIdCache;
	}

	public CookieRetrievingCookieGenerator getTgtCookieGenerator() {
		return this.tgtCookieGenerator;
	}

	public void setTgtCookieGenerator(final CookieRetrievingCookieGenerator tgtCookieGenerator) {
		this.tgtCookieGenerator = tgtCookieGenerator;
	}

}
