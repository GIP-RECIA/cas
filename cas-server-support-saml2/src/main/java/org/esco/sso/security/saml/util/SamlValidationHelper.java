/**
 * 
 */
package org.esco.sso.security.saml.util;

import org.esco.sso.security.saml.exception.SamlValidationException;
import org.joda.time.DateTime;
import org.joda.time.Instant;

/**
 * SAML Validation helper.
 * 
 * @author GIP RECIA 2013 - Maxime BOSSARD.
 *
 */
public abstract class SamlValidationHelper {

	/**
	 * Validate times notBefore and notOnOrAfter conditions.
	 * 
	 * @param clockSkewSeconds allowed time shift
	 * @param notBefore notBefore condition
	 * @param notOnOrAfter notOnOrAfter condition
	 * @throws SamlValidationException
	 *             in case of validation problem.
	 */
	public static void validateTimes(final int clockSkewSeconds, final DateTime notBefore,
			final DateTime notOnOrAfter) throws SamlValidationException {
		Instant serverInstant = new Instant();

		if (notBefore != null) {
			// Instant with skew
			Instant notBeforeInstant = notBefore.toInstant().withDurationAdded(clockSkewSeconds * 1000, -1);

			if (serverInstant.isBefore(notBeforeInstant)) {
				throw new SamlValidationException(
						"SAML 2.0 Message is outdated (too early) !");
			}
		}

		if ((notOnOrAfter != null)) {
			// Instant with skew
			Instant notOrOnAfterInstant = notOnOrAfter.toInstant().withDurationAdded(
					(clockSkewSeconds * 1000) - 1, 1);

			if (serverInstant.isAfter(notOrOnAfterInstant)) {
				throw new SamlValidationException(
						"SAML 2.0 Message is outdated (too late) !");
			}
		}

	}

}
