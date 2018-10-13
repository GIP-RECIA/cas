
package org.apereo.cas;

import org.apereo.cas.pm.web.flow.actions.VerifySecurityQuestionsActionTests;
import org.apereo.cas.pm.web.flow.actions.SendPasswordResetInstructionsActionTests;
import org.apereo.cas.pm.web.flow.actions.InitPasswordResetActionTests;
import org.apereo.cas.pm.web.flow.actions.VerifyPasswordResetRequestActionTests;
import org.apereo.cas.pm.web.flow.actions.HandlePasswordExpirationWarningMessagesActionTests;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * This is {@link AllTestsSuite}.
 *
 * @author Auto-generated by Gradle Build
 * @since 6.0.0-RC3
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
    VerifySecurityQuestionsActionTests.class,
    SendPasswordResetInstructionsActionTests.class,
    InitPasswordResetActionTests.class,
    VerifyPasswordResetRequestActionTests.class,
    HandlePasswordExpirationWarningMessagesActionTests.class
})
public class AllTestsSuite {
}