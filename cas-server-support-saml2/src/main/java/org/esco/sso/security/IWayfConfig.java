/**
 * 
 */
package org.esco.sso.security;

import java.io.Serializable;
import java.util.List;

/**
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface IWayfConfig extends Serializable {

	/**
	 * Retrieve all IdPs config ordered.
	 * 
	 * @return an ordered list of IdPs config.
	 */
	List<IIdpConfig> getIdpsConfig();

	/**
	 * Find an IdP config from its Id.
	 * 
	 * @param id the IdP config Id
	 * @return the corresponding IdP config
	 */
	IIdpConfig findIdpConfigById(String id);

	/**
	 * IdP id parameter key in HTTP request.
	 * @return IdP id parameter key in HTTP request.
	 */
	String getIdpIdParamKey();
}
