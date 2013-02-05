/**
 * 
 */
package org.esco.sso.security.saml.opensaml;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * Test du SP Processor.
 * 
 * @author GIP RECIA 2012 - Maxime BOSSARD.
 *
 */
@RunWith(value=SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations="classpath:openSaml20SpProcessorContext.xml")
public class OpenSaml20SpProcessorTest {

	@Autowired
	private OpenSaml20SpProcessor spProcessor;

	@BeforeClass
	public static void initOpenSaml() throws ConfigurationException {
		DefaultBootstrap.bootstrap();
	}

	@Test(expected=ValidationException.class)
	public void testValidateTimesOutdatedInFuture() throws ValidationException {
		// Interval: NOW  +1H <  > +2H
		DateTime start = new DateTime().plus(60000 * 3600);
		DateTime end = new DateTime().plus(60000 * 7200);

		this.spProcessor.validateTimes(start, end);
	}

	@Test(expected=ValidationException.class)
	public void testValidateTimesOutdatedInPassed() throws ValidationException {
		// Interval: -2H <  > -1H  NOW
		DateTime start = new DateTime().minus(60000 * 7200);
		DateTime end = new DateTime().minus(60000 * 3600);

		this.spProcessor.validateTimes(start, end);
	}

	@Test
	public void testValidateTimesOkWithoutSkew() throws ValidationException {
		// Interval: -1H < NOW > +1H
		DateTime start = new DateTime().minus(60000 * 3600);
		DateTime end = new DateTime().plus(60000 * 3600);

		this.spProcessor.validateTimes(start, end);
	}

	@Test
	public void testValidateTimesOkWithSkew1() throws ValidationException {
		// Interval: NOW +30s <  > +1H
		DateTime start = new DateTime().plus(30000);
		DateTime end = new DateTime().plus(60000 * 3600);

		this.spProcessor.validateTimes(start, end);
	}

	@Test
	public void testValidateTimesOkWithSkew2() throws ValidationException {
		// Interval: -1H <  > -30s NOW
		DateTime start = new DateTime().minus(60000 * 3600);
		DateTime end = new DateTime().minus(30000);

		this.spProcessor.validateTimes(start, end);
	}

	@Test(expected=ValidationException.class)
	public void testValidateTimesKoWithSkew() throws ValidationException {
		// Interval: -1H <  > -65s NOW
		DateTime start = new DateTime().minus(60000 * 3600);
		DateTime end = new DateTime().minus(65000);

		this.spProcessor.validateTimes(start, end);
	}

	@Test
	public void testValidateTimesGMT() throws ValidationException {
		// Interval: -5m GMT+3 < NOW > +5m GMT-3
		DateTime startPlus3H = new DateTime(DateTimeZone.forOffsetHours(+3)).minus(60000 * 5);
		DateTime endMinus3H = new DateTime(DateTimeZone.forOffsetHours(-3)).plus(60000 * 5);
		this.spProcessor.validateTimes(startPlus3H, endMinus3H);
	}

	@Test
	public void testValidateTimesBeforeOnly() throws ValidationException {
		// Interval: -1H < NOW > infinite
		DateTime start = new DateTime().minus(60000 * 3600);
		this.spProcessor.validateTimes(start, null);
	}

	@Test
	public void testValidateTimesAfterOnly() throws ValidationException {
		// Interval: infinite < NOW > +1H
		DateTime end = new DateTime().plus(60000 * 3600);

		this.spProcessor.validateTimes(null, end);
	}

	@Test
	public void testValidateTimesNull() throws ValidationException {
		this.spProcessor.validateTimes(null, null);
	}

}
