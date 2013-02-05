/**
 * 
 */
package org.esco.sso.security;

import java.io.Serializable;
import java.security.PrivateKey;

import org.esco.sso.security.saml.SamlBindingEnum;
import org.opensaml.xml.security.x509.BasicX509Credential;

/**
 * SP configuration.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public interface ISpConfig extends Serializable {

	/** Service Provider Id. */
	String getId();

	/** Service Provider SAML entity ID. */
	String getEntityId();

	/** Service Provider description. */
	String getDescription();

	/** Service Provider representative picture. */
	String getPictureUrl();

	/**
	 * Service Provider endpoint URL for this binding.
	 * 
	 * @param binding the binding
	 * @return the endpoint URL
	 */
	String getEndpointUrl(SamlBindingEnum binding);

	/** Used to decrypt assertions. */
	PrivateKey getDecryptionKey();

	/** Used to sign requests. */
	PrivateKey getSigningKey();

	/** Used to encrypt assertions. */
	BasicX509Credential getDecryptionCredential();

	/** Used for something ?. */
	BasicX509Credential getSigningCredential();

}
