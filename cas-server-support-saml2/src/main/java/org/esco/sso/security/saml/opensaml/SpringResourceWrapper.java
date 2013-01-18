/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;

/**
 * Spring resource wrapper to an open saml resource.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
public class SpringResourceWrapper implements Resource {

	/** Logger. */
	private static final Log LOGGER = LogFactory.getLog(SpringResourceWrapper.class);

	/** Spring resource. */
	private org.springframework.core.io.Resource springResource;

	/**
	 * Constructor.
	 * 
	 * @param resource the spring resource to wrap.
	 */
	public SpringResourceWrapper(final org.springframework.core.io.Resource resource) {
		this.springResource = resource;
		
	}

	@Override
	public String getLocation() {
		String location = null;

		try {
			if (springResource.exists()) {
				location = new File(this.springResource.getURL().getFile()).getCanonicalPath();
			}
		} catch (IOException e) {
			// Do nothing
			SpringResourceWrapper.LOGGER.debug("It's not a file !", e);
		}
		if (location == null) {
			try {
				location = this.springResource.getURI().getPath();
			} catch (IOException e) {
				// Do nothing
				SpringResourceWrapper.LOGGER.debug("It's not an URI ether !", e);
			}
		}

		if (location == null) {
			try {
				location = this.springResource.getURL().getPath();
			} catch (IOException e) {
				// Do nothing
				SpringResourceWrapper.LOGGER.debug("It's not an URL ether !", e);
			}
		}

		return location;
	}

	@Override
	public boolean exists() throws ResourceException {
		return this.springResource.exists();
	}

	@Override
	public InputStream getInputStream() throws ResourceException {
		try {
			return this.springResource.getInputStream();
		} catch (IOException e) {
			throw new ResourceException(e);
		}
	}

	@Override
	public DateTime getLastModifiedTime() throws ResourceException {
		try {
			long time = this.springResource.lastModified();
			return new DateTime(time);
		} catch (IOException e) {
			throw new ResourceException(e);
		}
	}

}
