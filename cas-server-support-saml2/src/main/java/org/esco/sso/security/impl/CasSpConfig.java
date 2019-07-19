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
package org.esco.sso.security.impl;

import java.security.PrivateKey;
import java.security.spec.EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.esco.sso.security.ISpConfig;
import org.esco.sso.security.saml.SamlBindingEnum;
import org.esco.sso.security.saml.opensaml.OpenSamlHelper;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * SP Configuration for CAS.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class CasSpConfig implements ISpConfig, InitializingBean {

	/** SVUID. */
	private static final long serialVersionUID = 7578815619985801219L;

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(CasSpConfig.class);

	private String id;

	private String entityId;

	private String description;

	private String pictureUrl;

	private boolean isUseFriendlyName;

	private Resource decryptionKeyResource;

	private Class<EncodedKeySpec> decryptionKeySpec;

	private String decryptionKeyType;

	private PrivateKey decryptionKey;

	private Resource signingKeyResource;

	private Class<EncodedKeySpec> signingKeySpec;

	private String signingKeyType;

	private PrivateKey signingKey;

	/** Used to configure the SP. */
	private Resource spMetadata;

	/** SP metadata provider. */
	private MetadataProvider spMetadataProvider;

	private Map<SamlBindingEnum, AssertionConsumerService> spAssertionConsumerServices = new HashMap<SamlBindingEnum, AssertionConsumerService>();

	private Map<SamlBindingEnum, SingleLogoutService> spSingleLogoutServices = new HashMap<SamlBindingEnum, SingleLogoutService>();

	private Map<Integer, AttributeConsumingService> attributeConsumingServices = new HashMap<Integer, AttributeConsumingService>();

	private Map<UsageType, BasicX509Credential> spCredentials = new HashMap<UsageType, BasicX509Credential>();

	@Override
	public PrivateKey getDecryptionKey() {
		return this.decryptionKey;
	}

	@Override
	public PrivateKey getSigningKey() {
		return this.signingKey;
	}
	@Override
	public BasicX509Credential getSigningCredential() {
		return this.spCredentials.get(UsageType.SIGNING);
	}

	@Override
	public BasicX509Credential getDecryptionCredential() {
		return this.spCredentials.get(UsageType.ENCRYPTION);
	}

	@Override
	public String getEndpointUrl(final SamlBindingEnum binding) {
		AssertionConsumerService acService = this.spAssertionConsumerServices.get(binding);
		return acService.getLocation();
	}

	/**
	 * Process SP metadatas.
	 * 
	 * @throws MetadataProviderException
	 * @throws XMLParserException
	 * @throws ConfigurationException 
	 */
	protected void processSpMetadata() throws MetadataProviderException, XMLParserException, ConfigurationException {
		Assert.notNull(this.spMetadata, "No SP metadata provided !");
		Assert.isTrue(this.spMetadata.exists(), String.format(
				"SP metadata [%s] cannot be found !", this.spMetadata.getFilename()));

		DefaultBootstrap.bootstrap();

		this.spMetadataProvider = OpenSamlHelper.buildMetadataProvider(this.spMetadata);
		Assert.notNull(this.spMetadataProvider, "SP metadata provider wasn't build !");

		String spEntityId = this.getEntityId();
		EntityDescriptor spEntityDescriptor = this.spMetadataProvider.getEntityDescriptor(spEntityId);
		Assert.notNull(spEntityDescriptor, String.format("No entity descriptor found in SP metadata for SP entityId [%s]", spEntityId));

		SPSSODescriptor ssoDescriptors = spEntityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
		if (ssoDescriptors != null) {
			// Retrieve Assertion Consumer endpoints URL.
			List<AssertionConsumerService> acServices = ssoDescriptors.getAssertionConsumerServices();
			if (!CollectionUtils.isEmpty(acServices)) {
				for (AssertionConsumerService acService : acServices) {
					if (acService != null) {
						SamlBindingEnum binding = SamlBindingEnum.fromSamlUri(acService.getBinding());
						if (binding != null) {
							this.spAssertionConsumerServices.put(binding, acService);
						}
					}
				}
			}

			// Retrieve Single Logout endpoints URL.
			List<SingleLogoutService> slServices = ssoDescriptors.getSingleLogoutServices();
			if (!CollectionUtils.isEmpty(slServices)) {
				for (SingleLogoutService slService : slServices) {
					if (slService != null) {
						SamlBindingEnum binding = SamlBindingEnum.fromSamlUri(slService.getBinding());
						if (binding != null) {
							this.spSingleLogoutServices.put(binding, slService);
						}
					}
				}
			}

			// Retrieve AttributeConsumingInformations.
			List<AttributeConsumingService> attrConsumingServices = ssoDescriptors.getAttributeConsumingServices();
			if (!CollectionUtils.isEmpty(attrConsumingServices)) {
				for (AttributeConsumingService attrConsumingService : attrConsumingServices) {
					if (attrConsumingService != null) {
						this.attributeConsumingServices.put(attrConsumingService.getIndex(), attrConsumingService);
					}
				}
			}

			// Retrieve KeyDescriptors
			List<KeyDescriptor> keyDescriptors = ssoDescriptors.getKeyDescriptors();
			if (!CollectionUtils.isEmpty(keyDescriptors)) {
				for (KeyDescriptor keyDescriptor : keyDescriptors) {
					if (keyDescriptor != null) {
						UsageType usageType = keyDescriptor.getUse();
						org.opensaml.xml.signature.KeyInfo keyInfo = keyDescriptor.getKeyInfo();
						if (keyInfo != null) {
							MetadataCredentialResolver mcr = new MetadataCredentialResolver(this.spMetadataProvider);

							Criteria criteria1 = new UsageCriteria(keyDescriptor.getUse());
							Criteria criteria2 = new EntityIDCriteria(this.getEntityId());
							Criteria criteria3 = new MetadataCriteria(SPSSODescriptor.DEFAULT_ELEMENT_NAME, null);
							CriteriaSet criteriaSet = new CriteriaSet(criteria1);
							criteriaSet.add(criteria2);
							criteriaSet.add(criteria3);
							try {
								BasicX509Credential credentials = (BasicX509Credential) mcr.resolveSingle(criteriaSet);
								this.spCredentials.put(usageType, credentials);
							} catch (SecurityException e) {
								CasSpConfig.LOGGER.error("Error while loading SP metadata credentials !", e);
							}
						}
					}
				}
			}
		}

		for (SamlBindingEnum binding : SamlBindingEnum.values()) {
			AssertionConsumerService service = this.spAssertionConsumerServices.get(binding);
			Assert.notNull(service, String.format(
					"No AssertionConsumingService for binding [%s] found in the SP metadata with entityId [%s] !",
					binding.getDescription(), spEntityId));
			Assert.isTrue(StringUtils.hasText(service.getLocation()), String.format(
					"No AssertionConsumingService location provided in SP metadata for binding [%s]", binding));
		}

		for (SamlBindingEnum binding : SamlBindingEnum.values()) {
			SingleLogoutService service = this.spSingleLogoutServices.get(binding);
			Assert.notNull(service,
					String.format("No SingleLogoutService for binding [%s] found in the SP metadata with entityId [%s] !",
							binding.getDescription(), spEntityId));
			Assert.isTrue(StringUtils.hasText(service.getLocation()), String.format(
					"No SingleLogoutService location provided in SP metadata for binding [%s]", binding));
		}

		BasicX509Credential signingCredential = this.spCredentials.get(UsageType.SIGNING);
		Assert.notNull(signingCredential, "No signing credential provided in SP metadata !");

		BasicX509Credential encryptionCredential = this.spCredentials.get(UsageType.ENCRYPTION);
		if (encryptionCredential == null) {
			this.spCredentials.put(UsageType.ENCRYPTION, signingCredential);
		}
	}

	/**
	 * Build private Keys.
	 *
	 * @throws Exception
	 */
	protected void buildSpPrivateKeys() throws Exception {
		Assert.notNull(this.decryptionKeyResource, "No encryption key configured for CAS SP");
		Assert.notNull(this.decryptionKeySpec, "No java encryption key specification configured for CAS SP");
		Assert.notNull(this.decryptionKeyType, "No encryption key type configured for CAS SP");
		Assert.notNull(this.signingKeyResource, "No signing key configured for CAS SP");
		Assert.notNull(this.signingKeySpec, "No java signing key specification configured for CAS SP");
		Assert.notNull(this.signingKeyType, "No signing key type configured for CAS SP");

		this.decryptionKey = SecurityHelper.buildPrivateKey(this.decryptionKeyResource, this.decryptionKeySpec, this.decryptionKeyType);
		this.signingKey = SecurityHelper.buildPrivateKey(this.signingKeyResource, this.signingKeySpec, this.signingKeyType);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notNull(this.id, "No id configured for CAS SP.");
		Assert.notNull(this.entityId, "No name configured for CAS SP");

		this.processSpMetadata();

		this.buildSpPrivateKeys();
	}

	@Override
	public String getId() {
		return this.id;
	}

	public void setId(final String id) {
		this.id = id;
	}

	@Override
	public String getEntityId() {
		return this.entityId;
	}

	public void setEntityId(final String entityId) {
		this.entityId = entityId;
	}

	@Override
	public String getDescription() {
		return this.description;
	}

	public void setDescription(final String description) {
		this.description = description;
	}

	@Override
	public String getPictureUrl() {
		return this.pictureUrl;
	}

	public void setPictureUrl(final String pictureUrl) {
		this.pictureUrl = pictureUrl;
	}

	@Override
	public boolean isUseFriendlyName() {
		return isUseFriendlyName;
	}

	public void setUseFriendlyName(final boolean useFriendlyName) {
		isUseFriendlyName = useFriendlyName;
	}

	public Resource getDecryptionKeyResource() {
		return this.decryptionKeyResource;
	}

	public void setDecryptionKeyResource(final Resource decryptionKeyResource) {
		this.decryptionKeyResource = decryptionKeyResource;
	}

	public Resource getSigningKeyResource() {
		return this.signingKeyResource;
	}

	public void setSigningKeyResource(final Resource signingKeyResource) {
		this.signingKeyResource = signingKeyResource;
	}

	public void setDecryptionKeyType(final String encryptionKeyType) {
		this.decryptionKeyType = encryptionKeyType;
	}

	public void setSigningKeyType(final String signingKeyType) {
		this.signingKeyType = signingKeyType;
	}

	public void setDecryptionKeySpec(final Class<EncodedKeySpec> encryptionKeySpec) {
		this.decryptionKeySpec = encryptionKeySpec;
	}

	public void setSigningKeySpec(final Class<EncodedKeySpec> signingKeySpec) {
		this.signingKeySpec = signingKeySpec;
	}

	public void setSpMetadata(final Resource spMetadata) {
		this.spMetadata = spMetadata;
	}

}
