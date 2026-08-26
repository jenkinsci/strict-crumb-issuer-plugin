/*
 * The MIT License
 *
 * Copyright (c) 2019-2023, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.strictcrumbissuer;

import static org.jenkinsci.plugins.strictcrumbissuer.StrictCrumbIssuer.HEADER_X_FORWARDED_FOR;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import hudson.model.User;
import hudson.security.csrf.CrumbIssuer;
import hudson.security.csrf.CrumbIssuerDescriptor;
import java.lang.reflect.Method;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import jenkins.model.Jenkins;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.WebResponse;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.kohsuke.stapler.StaplerRequest;

@WithJenkins
class StrictCrumbIssuerTest {

    private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    private static final String[] REFERER_TEST_SET = {
        "10.2.3.1", "10.2.3.1,10.20.30.40", "10.2.3.1,10.20.30.41", "10.2.3.3,10.20.30.40,10.20.30.41"
    };

    private JenkinsRule j;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
    }

    @Issue("JENKINS-3854")
    @Test
    void ipFromHeaderIsCorrectlyUsed() throws Exception {
        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING().withCheckClientIP(true)));

        checkClientIPFromHeader();
        checkHeaderChange();
        checkProxyIPChanged();
        checkProxyIPChain();
    }

    private void checkClientIPFromHeader() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HEADER_X_FORWARDED_FOR, REFERER_TEST_SET[0]);
        HtmlPage p = wc.goTo("configure");
        j.submit(p.getFormByName("config"));
    }

    private void checkHeaderChange() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HEADER_X_FORWARDED_FOR, REFERER_TEST_SET[0]);
        HtmlPage p = wc.goTo("configure");

        wc.removeRequestHeader(HEADER_X_FORWARDED_FOR);

        // The crumb should no longer match if we remove the proxy info
        FailingHttpStatusCodeException e =
                assertThrows(FailingHttpStatusCodeException.class, () -> j.submit(p.getFormByName("config")));
        assertEquals(403, e.getStatusCode());
    }

    private void checkProxyIPChanged() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HEADER_X_FORWARDED_FOR, REFERER_TEST_SET[1]);
        HtmlPage p = wc.goTo("configure");

        wc.removeRequestHeader(HEADER_X_FORWARDED_FOR);
        wc.addRequestHeader(HEADER_X_FORWARDED_FOR, REFERER_TEST_SET[2]);

        // The crumb should be the same even if the proxy IP changes
        j.submit(p.getFormByName("config"));
    }

    private void checkProxyIPChain() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HEADER_X_FORWARDED_FOR, REFERER_TEST_SET[3]);
        HtmlPage p = wc.goTo("configure");
        j.submit(p.getFormByName("config"));
    }

    @Issue("JENKINS-7518")
    @Test
    void proxyCompatibilityMode() throws Exception {
        j.jenkins.setCrumbIssuer(createStrict(Options.ALL().withCheckClientIP(false)));

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.addRequestHeader(HEADER_X_FORWARDED_FOR, REFERER_TEST_SET[0]);
        HtmlPage p = wc.goTo("configure");

        wc.removeRequestHeader(HEADER_X_FORWARDED_FOR);
        // The crumb should still match if we remove the proxy info
        j.submit(p.getFormByName("config"));
    }

    @Test
    void checkSameSource() throws Exception {
        checkSameSource_fullUrl();
        checkSameSource_onlyLocalPath();
    }

    private void checkSameSource_fullUrl() throws Exception {
        j.jenkins.setCrumbIssuer(
                createStrict(Options.NOTHING().withCheckSameSource(true).withCheckOnlyLocalPath(false)));

        URL url = j.getURL();

        JenkinsRule.WebClient wc = j.createWebClient();
        HtmlPage page1 =
                (HtmlPage) wc.getPage("http://127.0.0.1:" + url.getPort() + j.contextPath + "/configure?a=b&c=d");
        String crumb1 = page1.getElementByName("Jenkins-Crumb").getAttribute("value");
        j.submit(page1.getFormByName("config"));

        // rootUrl changed
        HtmlPage page2 = wc.goTo("configure?a=b&c=d");
        String crumb2 = page2.getElementByName("Jenkins-Crumb").getAttribute("value");
        assertNotEquals(crumb1, crumb2);
        j.submit(page2.getFormByName("config"));

        // the token from page 1 will not work with page 2 as the root url differ
        replaceAllCrumbInPageBy(page2, crumb1);

        FailingHttpStatusCodeException e =
                assertThrows(FailingHttpStatusCodeException.class, () -> j.submit(page2.getFormByName("config")));
        WebResponse response = e.getResponse();
        String responseBody = response.getContentAsString();
        assertTrue(responseBody.contains("No valid crumb"));

        // same url, second hit
        HtmlPage page2b = wc.goTo("configure?a=b&c=d");
        String crumb2b = page2b.getElementByName("Jenkins-Crumb").getAttribute("value");
        assertEquals(crumb2, crumb2b);
        j.submit(page2b.getFormByName("config"));

        // simple change in query
        HtmlPage page3 = wc.goTo("configure?e=f");
        String crumb3 = page3.getElementByName("Jenkins-Crumb").getAttribute("value");
        assertNotEquals(crumb2, crumb3);
        j.submit(page3.getFormByName("config"));

        // even page 2 and 3 have the same root url, we also check the query (and rest of the url)
        replaceAllCrumbInPageBy(page3, crumb2);

        e = assertThrows(FailingHttpStatusCodeException.class, () -> j.submit(page3.getFormByName("config")));
        response = e.getResponse();
        responseBody = response.getContentAsString();
        assertTrue(responseBody.contains("No valid crumb"));
    }

    private void checkSameSource_onlyLocalPath() throws Exception {
        j.jenkins.setCrumbIssuer(
                createStrict(Options.NOTHING().withCheckSameSource(true).withCheckOnlyLocalPath(true)));

        URL url = j.getURL();

        JenkinsRule.WebClient wc = j.createWebClient();
        HtmlPage page1 =
                (HtmlPage) wc.getPage("http://127.0.0.1:" + url.getPort() + j.contextPath + "/configure?a=b&c=d");
        String crumb1 = page1.getElementByName("Jenkins-Crumb").getAttribute("value");
        j.submit(page1.getFormByName("config"));

        // rootUrl changed
        HtmlPage page2 = wc.goTo("configure?a=b&c=d");
        String crumb2 = page2.getElementByName("Jenkins-Crumb").getAttribute("value");
        assertEquals(crumb1, crumb2);
        j.submit(page2.getFormByName("config"));

        // same url, second hit
        HtmlPage page2b = wc.goTo("configure?a=b&c=d");
        String crumb2b = page2b.getElementByName("Jenkins-Crumb").getAttribute("value");
        assertEquals(crumb2, crumb2b);
        j.submit(page2b.getFormByName("config"));

        // simple change in query
        HtmlPage page3 = wc.goTo("configure?e=f");
        String crumb3 = page3.getElementByName("Jenkins-Crumb").getAttribute("value");
        assertNotEquals(crumb2, crumb3);
        j.submit(page3.getFormByName("config"));

        // we check just the local path of the url
        replaceAllCrumbInPageBy(page3, crumb2);

        FailingHttpStatusCodeException e =
                assertThrows(FailingHttpStatusCodeException.class, () -> j.submit(page3.getFormByName("config")));
        WebResponse response = e.getResponse();
        String responseBody = response.getContentAsString();
        assertTrue(responseBody.contains("No valid crumb"));
    }

    private void replaceAllCrumbInPageBy(HtmlPage page, String newCrumb) {
        for (DomElement el : page.getElementsByName("Jenkins-Crumb")) {
            el.setAttribute("value", newCrumb);
        }
    }

    @Test
    void successiveCrumb_mustBeValidAndDifferent() {
        CrumbIssuer crumbIssuer = createStrict(Options.NOTHING());
        checkSuccessiveCrumbMustBeValidAndDifferent(crumbIssuer, false);

        crumbIssuer = createStrict(Options.NOTHING().withXorMasking(true));
        checkSuccessiveCrumbMustBeValidAndDifferent(crumbIssuer, true);
    }

    private void checkSuccessiveCrumbMustBeValidAndDifferent(CrumbIssuer crumbIssuer, boolean different) {
        StaplerRequest request = createMockRequest("/jenkins");
        String csrfToken1 = crumbIssuer.getCrumb(request);
        crumbIssuer.validateCrumb(request);

        request = createMockRequest("/jenkins");
        String csrfToken2 = crumbIssuer.getCrumb(request);
        crumbIssuer.validateCrumb(request);

        if (different) {
            assertNotEquals(csrfToken1, csrfToken2);
        } else {
            assertEquals(csrfToken1, csrfToken2);
        }
    }

    private StaplerRequest createMockRequest(String contextPath) {
        StaplerRequest req = mock(StaplerRequest.class);
        when(req.getContextPath()).thenReturn(contextPath);
        when(req.getRequestURI()).thenReturn(contextPath + "/configure");
        return req;
    }

    @Test
    void durationMustBeValid() throws Exception {
        // in the past and also in the future
        StrictCrumbIssuer strictCrumbIssuer = spy(createStrict(Options.NOTHING().withHoursValid(3)));
        StaplerRequest request;

        // to avoid problem with the spied class
        doReturn((CrumbIssuerDescriptor<CrumbIssuer>) Jenkins.get().getDescriptorOrDie(StrictCrumbIssuer.class))
                .when(strictCrumbIssuer)
                .getDescriptor();

        // hypothesis, time is November 23, 9:16:23pm (rounded to 9:15)
        // the validity period must be 9:15 - 12:19:59 to ensure at least 3 hours but less than 3h05
        Date date = new SimpleDateFormat(DATE_FORMAT).parse("2017-11-23T09:16:23");
        long nowHour = date.getTime() / (3600000 / 12);
        doReturn(nowHour).when(strictCrumbIssuer).getCurrentHour();

        request = createMockRequest("/jenkins");
        String crumb = strictCrumbIssuer.getCrumb(request);
        when(request.getParameter(anyString())).thenReturn(crumb);

        checkAllPossibilitiesForDate(strictCrumbIssuer, request, false);

        reset(strictCrumbIssuer);
    }

    @Test
    void durationIgnored_alwaysValid() throws Exception {
        // in the past and also in the future
        StrictCrumbIssuer strictCrumbIssuer = spy(createStrict(Options.NOTHING().withHoursValid(0)));
        StaplerRequest request;

        // to avoid problem with the spied class
        doReturn((CrumbIssuerDescriptor<CrumbIssuer>) Jenkins.get().getDescriptorOrDie(StrictCrumbIssuer.class))
                .when(strictCrumbIssuer)
                .getDescriptor();

        // hypothesis, time is November 23, 9:16:23pm (will be rounded to 9:15)
        // the validity period must be 9:15 - 12:19:59 to ensure at least 3 hours but less than 3h05
        Date date = new SimpleDateFormat(DATE_FORMAT).parse("2017-11-23T09:16:23");
        long nowHour = date.getTime() / (3600000 / 12);
        doReturn(nowHour).when(strictCrumbIssuer).getCurrentHour();

        request = createMockRequest("/jenkins");
        String crumb = strictCrumbIssuer.getCrumb(request);
        when(request.getParameter(anyString())).thenReturn(crumb);

        checkAllPossibilitiesForDate(strictCrumbIssuer, request, true);

        reset(strictCrumbIssuer);
    }

    private void checkAllPossibilitiesForDate(
            StrictCrumbIssuer strictCrumbIssuer, StaplerRequest request, boolean isAlwaysValid) throws Exception {
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T09:16:23", true);
        // just before
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T09:15:00", true);
        // after some minutes
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T09:35:00", true);
        // after one hour
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T10:25:00", true);
        // just before current time + hourValid
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T12:14:59", true);
        // just after
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T12:15:00", true);
        // last moment (due to 5 minutes precision)
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T12:19:59", true);

        // after the validity period
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T12:20:00", isAlwaysValid);
        // more than 5 minutes (rounded) before
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-23T09:14:59", isAlwaysValid);
        // days after
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-25T10:00:00", isAlwaysValid);
        // days before
        checkCrumbIsValidAt(strictCrumbIssuer, request, "2017-11-13T20:00:00", isAlwaysValid);
    }

    private void checkCrumbIsValidAt(
            StrictCrumbIssuer strictCrumbIssuer, StaplerRequest request, String dateString, boolean mustBeValid)
            throws Exception {
        Date date = new SimpleDateFormat(DATE_FORMAT).parse(dateString);
        long nowHour = date.getTime() / (3600000 / 12);
        doReturn(nowHour).when(strictCrumbIssuer).getCurrentHour();

        assertEquals(mustBeValid, strictCrumbIssuer.validateCrumb(request));
    }

    @Test
    void crumbOnlyValidForUniqueUser() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING()));

        User.getById("foo", true);
        User.getById("bar", true);

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("foo");

        HtmlPage fooPage = wc.goTo("configure");
        j.submit(fooPage.getFormByName("config"));

        wc.login("bar");
        HtmlPage barPage = wc.goTo("configure");
        j.submit(barPage.getFormByName("config"));

        // submit the form with foo crumb
        FailingHttpStatusCodeException e =
                assertThrows(FailingHttpStatusCodeException.class, () -> j.submit(fooPage.getFormByName("config")));
        WebResponse response = e.getResponse();
        String responseBody = response.getContentAsString();
        assertTrue(responseBody.contains("No valid crumb"));
    }

    @Test
    void crumbOnlyValidForOneSession() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());

        User.getById("foo", true);

        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING().withCheckSessionMatch(false)));
        checkAfterLogout_tokenAreEqual(true);

        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING().withCheckSessionMatch(true)));
        checkAfterLogout_tokenAreEqual(false);
    }

    private void checkAfterLogout_tokenAreEqual(boolean areEqual) throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("foo");

        HtmlPage page1 = wc.goTo("configure");
        String crumb1 = page1.getElementByName("Jenkins-Crumb").getAttribute("value");
        j.submit(page1.getFormByName("config"));

        wc.goTo("logout");
        wc.login("foo");

        HtmlPage page2 = wc.goTo("configure");
        String crumb2 = page2.getElementByName("Jenkins-Crumb").getAttribute("value");
        j.submit(page2.getFormByName("config"));

        assertEquals(crumb1.equals(crumb2), areEqual);

        replaceAllCrumbInPageBy(page2, crumb1);
        if (areEqual) {
            j.submit(page2.getFormByName("config"));
        } else {
            // submit the form with foo crumb
            FailingHttpStatusCodeException e =
                    assertThrows(FailingHttpStatusCodeException.class, () -> j.submit(page2.getFormByName("config")));
            WebResponse response = e.getResponse();
            String responseBody = response.getContentAsString();
            assertTrue(responseBody.contains("No valid crumb"));
        }
    }

    @Test
    void setupCrumbIssuerInWebUI() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING()));

        User.getById("foo", true);

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("foo");

        configureIssuerUsingWebUI(wc, true, null, null, null, null, null);
        assertTrue(currentIssuer().isCheckClientIP());
        configureIssuerUsingWebUI(wc, false, null, null, null, null, null);
        assertFalse(currentIssuer().isCheckClientIP());

        configureIssuerUsingWebUI(wc, null, true, null, null, null, null);
        assertTrue(currentIssuer().isCheckSameSource());
        configureIssuerUsingWebUI(wc, null, false, null, null, null, null);
        assertFalse(currentIssuer().isCheckSameSource());

        configureIssuerUsingWebUI(wc, null, null, true, null, null, null);
        assertTrue(currentIssuer().isCheckOnlyLocalPath());
        configureIssuerUsingWebUI(wc, null, null, false, null, null, null);
        assertFalse(currentIssuer().isCheckOnlyLocalPath());

        configureIssuerUsingWebUI(wc, null, null, null, true, null, null);
        assertTrue(currentIssuer().isCheckSessionMatch());
        configureIssuerUsingWebUI(wc, null, null, null, false, null, null);
        assertFalse(currentIssuer().isCheckSessionMatch());

        configureIssuerUsingWebUI(wc, null, null, null, null, null, true);
        assertTrue(currentIssuer().isXorMasking());
        configureIssuerUsingWebUI(wc, null, null, null, null, null, false);
        assertFalse(currentIssuer().isXorMasking());

        configureIssuerUsingWebUI(wc, null, null, null, null, -3, null);
        assertEquals(0, currentIssuer().getHoursValid());
        configureIssuerUsingWebUI(wc, null, null, null, null, 0, null);
        assertEquals(0, currentIssuer().getHoursValid());
        configureIssuerUsingWebUI(wc, null, null, null, null, 1, null);
        assertEquals(1, currentIssuer().getHoursValid());
        configureIssuerUsingWebUI(wc, null, null, null, null, 24, null);
        assertEquals(24, currentIssuer().getHoursValid());
        configureIssuerUsingWebUI(wc, null, null, null, null, 25, null);
        assertEquals(24, currentIssuer().getHoursValid());
    }

    private StrictCrumbIssuer currentIssuer() {
        return (StrictCrumbIssuer) j.jenkins.getCrumbIssuer();
    }

    private void configureIssuerUsingWebUI(
            JenkinsRule.WebClient wc,
            Boolean checkClientIP,
            Boolean checkSameSource,
            Boolean checkOnlyLocalPath,
            Boolean checkSessionMatch,
            Integer hoursValid,
            Boolean xorMasking)
            throws Exception {
        HtmlPage p = wc.goTo("configureSecurity");
        HtmlForm form = p.getFormByName("config");
        if (checkClientIP != null) {
            form.getInputByName("_.checkClientIP").setChecked(checkClientIP);
        }
        if (checkSameSource != null) {
            form.getInputByName("_.checkSameSource").setChecked(checkSameSource);
        }
        if (checkOnlyLocalPath != null) {
            form.getInputByName("_.checkOnlyLocalPath").setChecked(checkOnlyLocalPath);
        }
        if (checkSessionMatch != null) {
            form.getInputByName("_.checkSessionMatch").setChecked(checkSessionMatch);
        }
        if (hoursValid != null) {
            form.getInputByName("_.hoursValid").setValue("" + hoursValid);
        }
        if (xorMasking != null) {
            form.getInputByName("_.xorMasking").setChecked(xorMasking);
        }
        HtmlPage result = j.submit(form);
        assertEquals(200, result.getWebResponse().getStatusCode());
    }

    @Test
    @WithoutJenkins
    void checkTheHourValidRange() {
        // common case
        assertEquals(1, createStrict(Options.NOTHING().withHoursValid(1)).getHoursValid());
        assertEquals(12, createStrict(Options.NOTHING().withHoursValid(12)).getHoursValid());
        assertEquals(24, createStrict(Options.NOTHING().withHoursValid(24)).getHoursValid());

        // out of boundaries
        assertEquals(0, createStrict(Options.NOTHING().withHoursValid(-1)).getHoursValid());
        assertEquals(0, createStrict(Options.NOTHING().withHoursValid(-10)).getHoursValid());
        assertEquals(24, createStrict(Options.NOTHING().withHoursValid(25)).getHoursValid());
        assertEquals(24, createStrict(Options.NOTHING().withHoursValid(15235)).getHoursValid());
    }

    @Test
    @WithoutJenkins
    void checkXorCorrect() throws Exception {
        checkReversibleXor("abcd", "1234");
        checkReversibleXor("1234567890abcdef", "737af387278abc1e");

        // beginning with 0
        checkReversibleXor("0123", "137a");
        // 0 for seed
        checkReversibleXor("137a", "0123");
        // multiple zero
        checkReversibleXor("0002", "137a");
        // all zeros
        checkReversibleXor("0000", "137a");

        // same start => intermediate will have 0 as first
        checkReversibleXor("2346", "2764");
    }

    private void checkReversibleXor(String secret, String seed) throws Exception {
        StrictCrumbIssuer crumbIssuer = createStrict(Options.ALL());
        Method xorMethod = crumbIssuer.getClass().getDeclaredMethod("xor", String.class, String.class);

        xorMethod.setAccessible(true);
        String intermediate = (String) xorMethod.invoke(crumbIssuer, secret, seed);
        String result = (String) xorMethod.invoke(crumbIssuer, intermediate, seed);

        assertEquals(result, secret);
    }

    private StrictCrumbIssuer createStrict(Options options) {
        return new StrictCrumbIssuer(
                options.checkClientIP,
                options.checkSameSource,
                options.checkOnlyLocalPath,
                options.checkSessionMatch,
                options.hoursValid,
                options.xorMasking);
    }

    private static class Options {
        boolean checkClientIP;
        boolean checkSameSource;
        boolean checkOnlyLocalPath;
        boolean checkSessionMatch;
        int hoursValid;
        boolean xorMasking;

        static Options ALL() {
            return new Options()
                    .withCheckClientIP(true)
                    .withCheckSameSource(true)
                    .withCheckOnlyLocalPath(true)
                    .withCheckSessionMatch(true)
                    .withHoursValid(12)
                    .withXorMasking(true);
        }

        static Options NOTHING() {
            return new Options()
                    .withCheckClientIP(false)
                    .withCheckSameSource(false)
                    .withCheckOnlyLocalPath(false)
                    .withCheckSessionMatch(false)
                    .withHoursValid(0)
                    .withXorMasking(false);
        }

        Options withCheckClientIP(boolean value) {
            this.checkClientIP = value;
            return this;
        }

        Options withCheckSameSource(boolean value) {
            this.checkSameSource = value;
            return this;
        }

        Options withCheckOnlyLocalPath(boolean value) {
            this.checkOnlyLocalPath = value;
            return this;
        }

        Options withCheckSessionMatch(boolean value) {
            this.checkSessionMatch = value;
            return this;
        }

        Options withHoursValid(int value) {
            this.hoursValid = value;
            return this;
        }

        Options withXorMasking(boolean value) {
            this.xorMasking = value;
            return this;
        }
    }
}
