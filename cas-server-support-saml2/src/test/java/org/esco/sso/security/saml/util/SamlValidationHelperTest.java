/**
 * 
 */
package org.esco.sso.security.saml.util;

import org.esco.sso.security.saml.exception.SamlValidationException;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;

/**
 * Test du SP Processor.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=BlockJUnit4ClassRunner.class)
public class SamlValidationHelperTest {

	/** Clock Skew Seconds. */
	private static final int CSS = 60;

	@Test(expected=SamlValidationException.class)
	public void testValidateTimesOutdatedInFuture() throws Exception {
		// Interval: NOW  +1H <  > +2H
		DateTime start = new DateTime().plus(60000 * 3600);
		DateTime end = new DateTime().plus(60000 * 7200);

		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, start, end);
	}

	@Test(expected=SamlValidationException.class)
	public void testValidateTimesOutdatedInPassed() throws Exception {
		// Interval: -2H <  > -1H  NOW
		DateTime start = new DateTime().minus(60000 * 7200);
		DateTime end = new DateTime().minus(60000 * 3600);

		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, start, end);
	}

	@Test
	public void testValidateTimesOkWithoutSkew() throws Exception {
		// Interval: -1H < NOW > +1H
		DateTime start = new DateTime().minus(60000 * 3600);
		DateTime end = new DateTime().plus(60000 * 3600);

		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, start, end);
	}

	@Test
	public void testValidateTimesOkWithSkew1() throws Exception {
		// Interval: NOW +30s <  > +1H
		DateTime start = new DateTime().plus(30000);
		DateTime end = new DateTime().plus(60000 * 3600);

		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, start, end);
	}

	@Test
	public void testValidateTimesOkWithSkew2() throws Exception {
		// Interval: -1H <  > -30s NOW
		DateTime start = new DateTime().minus(60000 * 3600);
		DateTime end = new DateTime().minus(30000);

		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, start, end);
	}

	@Test(expected=SamlValidationException.class)
	public void testValidateTimesKoWithSkew() throws Exception {
		// Interval: -1H <  > -65s NOW
		DateTime start = new DateTime().minus(60000 * 3600);
		DateTime end = new DateTime().minus(65000);

		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, start, end);
	}

	@Test
	public void testValidateTimesGMT() throws Exception {
		// Interval: -5m GMT+3 < NOW > +5m GMT-3
		DateTime startPlus3H = new DateTime(DateTimeZone.forOffsetHours(+3)).minus(60000 * 5);
		DateTime endMinus3H = new DateTime(DateTimeZone.forOffsetHours(-3)).plus(60000 * 5);
		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, startPlus3H, endMinus3H);
	}

	@Test
	public void testValidateTimesBeforeOnly() throws Exception {
		// Interval: -1H < NOW > infinite
		DateTime start = new DateTime().minus(60000 * 3600);
		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, start, null);
	}

	@Test
	public void testValidateTimesAfterOnly() throws Exception {
		// Interval: infinite < NOW > +1H
		DateTime end = new DateTime().plus(60000 * 3600);

		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, null, end);
	}

	@Test
	public void testValidateTimesNull() throws Exception {
		SamlValidationHelper.validateTimes(SamlValidationHelperTest.CSS, null, null);
	}

}
