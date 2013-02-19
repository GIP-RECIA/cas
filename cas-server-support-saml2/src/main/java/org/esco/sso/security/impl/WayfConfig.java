/**
 * 
 */
package org.esco.sso.security.impl;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.esco.sso.security.IIdpConfig;
import org.esco.sso.security.IWayfConfig;
import org.esco.sso.security.saml.util.SamlHelper;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class WayfConfig implements IWayfConfig, InitializingBean {

	/** SVUID. */
	private static final long serialVersionUID = -8041965026650236495L;

	/** IdPs configuration map. */
	private Map <String, IIdpConfig> idpConfigs;

	/** IdPs configuration ordered list. */
	private List <IIdpConfig> idpConfigsList;

	/** IdP id parameter key in HTTP request. */
	private String idpIdParamKey;

	@Override
	public IIdpConfig findIdpConfigById(final String id) {
		return this.idpConfigs.get(id);
	}

	@Override
	public List<IIdpConfig> getIdpsConfig() {
		return this.idpConfigsList;
	}

	/**
	 * IdPs configuration ordered list.
	 * 
	 * @param idpConfigs IdPs configuration ordered list
	 */
	public void setConfig(final List<IIdpConfig> idpConfigs) {
		Assert.notEmpty(idpConfigs, "IdP config ordered list is empty !");
		this.idpConfigsList = idpConfigs;
		this.idpConfigs = new HashMap<String, IIdpConfig>();
		for (IIdpConfig config : idpConfigs) {
			IIdpConfig previous = this.idpConfigs.put(config.getId(), config);
			Assert.isNull(previous, String.format(
					"Two IdP configs owned the same unique Id: [%s] !", previous));
			config.registerWayfConfig(this);
		}
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.notEmpty(this.idpConfigs, "No IdP Config supplied !");
		Assert.notNull(this.idpIdParamKey, "No IdP id parameter key configured !");

		// Register this config in the Helper
		SamlHelper.registerWayfConfig(this);
	}

	/**
	 * IdP id parameter key in HTTP request.
	 * 
	 * @return IdP id parameter key in HTTP request.
	 */
	@Override
	public String getIdpIdParamKey() {
		return this.idpIdParamKey;
	}

	/**
	 * IdP id parameter key in HTTP request.
	 * 
	 * @param idpIdParamKey
	 */
	public void setIdpIdParamKey(final String idpIdParamKey) {
		this.idpIdParamKey = idpIdParamKey;
	}

}
