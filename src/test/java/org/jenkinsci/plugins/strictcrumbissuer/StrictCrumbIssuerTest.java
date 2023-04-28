/*
 * The MIT License
 *
 * Copyright (c) 2019, CloudBees, Inc.
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

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.common.net.HttpHeaders;
import hudson.model.User;
import hudson.security.csrf.CrumbIssuer;
import hudson.security.csrf.CrumbIssuerDescriptor;
import jenkins.model.Jenkins;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.WithoutJenkins;
import org.kohsuke.stapler.StaplerRequest;
import org.mockito.Mockito;

import java.lang.reflect.Method;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

public class StrictCrumbIssuerTest {

    private static final String[] refererTestSet = {
            "10.2.3.1",
            "10.2.3.1,10.20.30.40",
            "10.2.3.1,10.20.30.41",
            "10.2.3.3,10.20.30.40,10.20.30.41"
    };

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Issue("JENKINS-3854")
    @Test
    public void ipFromHeaderIsCorrectlyUsed() throws Exception {
        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING().withCheckClientIP(true)));

        this.checkClientIPFromHeader();
        this.checkHeaderChange();
        this.checkProxyIPChanged();
        this.checkProxyIPChain();
    }

    private void checkClientIPFromHeader() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HttpHeaders.X_FORWARDED_FOR, refererTestSet[0]);
        HtmlPage p = wc.goTo("configure");
        j.submit(p.getFormByName("config"));
    }

    private void checkHeaderChange() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HttpHeaders.X_FORWARDED_FOR, refererTestSet[0]);
        HtmlPage p = wc.goTo("configure");

        wc.removeRequestHeader(HttpHeaders.X_FORWARDED_FOR);
        try {
            // The crumb should no longer match if we remove the proxy info
            j.submit(p.getFormByName("config"));
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(403, e.getStatusCode());
        }
    }

    private void checkProxyIPChanged() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HttpHeaders.X_FORWARDED_FOR, refererTestSet[1]);
        HtmlPage p = wc.goTo("configure");

        wc.removeRequestHeader(HttpHeaders.X_FORWARDED_FOR);
        wc.addRequestHeader(HttpHeaders.X_FORWARDED_FOR, refererTestSet[2]);

        // The crumb should be the same even if the proxy IP changes
        j.submit(p.getFormByName("config"));
    }

    private void checkProxyIPChain() throws Exception {
        JenkinsRule.WebClient wc = j.createWebClient();

        wc.addRequestHeader(HttpHeaders.X_FORWARDED_FOR, refererTestSet[3]);
        HtmlPage p = wc.goTo("configure");
        j.submit(p.getFormByName("config"));
    }

    @Issue("JENKINS-7518")
    @Test
    public void proxyCompatibilityMode() throws Exception {
        j.jenkins.setCrumbIssuer(createStrict(Options.ALL().withCheckClientIP(false)));

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.addRequestHeader(HttpHeaders.X_FORWARDED_FOR, refererTestSet[0]);
        HtmlPage p = wc.goTo("configure");

        wc.removeRequestHeader(HttpHeaders.X_FORWARDED_FOR);
        // The crumb should still match if we remove the proxy info
        j.submit(p.getFormByName("config"));
    }

    @Test
    public void checkSameSource() throws Exception {
        checkSameSource_fullUrl();
        checkSameSource_onlyLocalPath();
    }

    private void checkSameSource_fullUrl() throws Exception {
        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING().withCheckSameSource(true).withCheckOnlyLocalPath(false)));

        URL url = j.getURL();

        JenkinsRule.WebClient wc = j.createWebClient();
        HtmlPage page1 = (HtmlPage) wc.getPage("http://127.0.0.1:" + url.getPort() + j.contextPath + "/configure?a=b&c=d");
        String crumb1 = page1.getElementByName("Jenkins-Crumb").getAttribute("value");
        j.submit(page1.getFormByName("config"));

        // rootUrl changed
        HtmlPage page2 = wc.goTo("configure?a=b&c=d");
        String crumb2 = page2.getElementByName("Jenkins-Crumb").getAttribute("value");
        assertNotEquals(crumb1, crumb2);
        j.submit(page2.getFormByName("config"));

        // the token from page 1 will not work with page 2 as the root url differ
        replaceAllCrumbInPageBy(page2, crumb1);
        try {
            j.submit(page2.getFormByName("config"));
            fail();
        } catch (FailingHttpStatusCodeException e) {
            WebResponse response = e.getResponse();
            String responseBody = response.getContentAsString();
            assertTrue(responseBody.contains("No valid crumb"));
        }

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
        try {
            j.submit(page3.getFormByName("config"));
            fail();
        } catch (FailingHttpStatusCodeException e) {
            WebResponse response = e.getResponse();
            String responseBody = response.getContentAsString();
            assertTrue(responseBody.contains("No valid crumb"));
        }
    }

    private void checkSameSource_onlyLocalPath() throws Exception {
        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING().withCheckSameSource(true).withCheckOnlyLocalPath(true)));

        URL url = j.getURL();

        JenkinsRule.WebClient wc = j.createWebClient();
        HtmlPage page1 = (HtmlPage) wc.getPage("http://127.0.0.1:" + url.getPort() + j.contextPath + "/configure?a=b&c=d");
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
        try {
            j.submit(page3.getFormByName("config"));
            fail();
        } catch (FailingHttpStatusCodeException e) {
            WebResponse response = e.getResponse();
            String responseBody = response.getContentAsString();
            assertTrue(responseBody.contains("No valid crumb"));
        }
    }

    private void replaceAllCrumbInPageBy(HtmlPage page, String newCrumb) {
        for (DomElement el : page.getElementsByName("Jenkins-Crumb")) {
            el.setAttribute("value", newCrumb);
        }
    }

    @Test
    public void successiveCrumb_mustBeValidAndDifferent() {
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

    private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    @Test
    public void durationMustBeValid() throws Exception {
        // in the past and also in the future
        StrictCrumbIssuer strictCrumbIssuer = spy(createStrict(Options.NOTHING().withHoursValid(3)));
        StaplerRequest request;

        // to avoid problem with the spied class
        Mockito.doReturn(
                (CrumbIssuerDescriptor<CrumbIssuer>) Jenkins.getInstance().getDescriptorOrDie(StrictCrumbIssuer.class)
        ).when(strictCrumbIssuer).getDescriptor();

        // hypothesis, time is November 23, 9:16:23pm (rounded to 9:15)
        // the validity period must be 9:15 - 12:19:59 to ensure at least 3 hours but less than 3h05
        Date date = new SimpleDateFormat(DATE_FORMAT).parse("2017-11-23T09:16:23");
        long nowHour = date.getTime() / (3600000 / 12);
        Mockito.doReturn(nowHour).when(strictCrumbIssuer).getCurrentHour();

        request = createMockRequest("/jenkins");
        String crumb = strictCrumbIssuer.getCrumb(request);
        when(request.getParameter(Mockito.anyString())).thenReturn(crumb);

        checkAllPossibilitiesForDate(strictCrumbIssuer, request, false);

        Mockito.reset(strictCrumbIssuer);
    }

    @Test
    public void durationIgnored_alwaysValid() throws Exception {
        // in the past and also in the future
        StrictCrumbIssuer strictCrumbIssuer = spy(createStrict(Options.NOTHING().withHoursValid(0)));
        StaplerRequest request;

        // to avoid problem with the spied class
        Mockito.doReturn(
                (CrumbIssuerDescriptor<CrumbIssuer>) Jenkins.getInstance().getDescriptorOrDie(StrictCrumbIssuer.class)
        ).when(strictCrumbIssuer).getDescriptor();

        // hypothesis, time is November 23, 9:16:23pm (will be rounded to 9:15)
        // the validity period must be 9:15 - 12:19:59 to ensure at least 3 hours but less than 3h05
        Date date = new SimpleDateFormat(DATE_FORMAT).parse("2017-11-23T09:16:23");
        long nowHour = date.getTime() / (3600000 / 12);
        Mockito.doReturn(nowHour).when(strictCrumbIssuer).getCurrentHour();

        request = createMockRequest("/jenkins");
        String crumb = strictCrumbIssuer.getCrumb(request);
        when(request.getParameter(Mockito.anyString())).thenReturn(crumb);

        checkAllPossibilitiesForDate(strictCrumbIssuer, request, true);

        Mockito.reset(strictCrumbIssuer);
    }

    private void checkAllPossibilitiesForDate(StrictCrumbIssuer strictCrumbIssuer, StaplerRequest request, boolean isAlwaysValid) throws Exception {
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

    private void checkCrumbIsValidAt(StrictCrumbIssuer strictCrumbIssuer, StaplerRequest request, String dateString, boolean mustBeValid) throws Exception {
        Date date = new SimpleDateFormat(DATE_FORMAT).parse(dateString);
        long nowHour = date.getTime() / (3600000 / 12);
        Mockito.doReturn(nowHour).when(strictCrumbIssuer).getCurrentHour();

        assertEquals(mustBeValid, strictCrumbIssuer.validateCrumb(request));
    }

    @Test
    public void crumbOnlyValidForUniqueUser() throws Exception {
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

        try {
            // submit the form with foo crumb
            j.submit(fooPage.getFormByName("config"));
            fail();
        } catch (FailingHttpStatusCodeException e) {
            WebResponse response = e.getResponse();
            String responseBody = response.getContentAsString();
            assertTrue(responseBody.contains("No valid crumb"));
        }
    }

    @Test
    public void crumbOnlyValidForOneSession() throws Exception {
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

        HtmlPage p = wc.goTo("configure");
        String crumb1 = p.getElementByName("Jenkins-Crumb").getAttribute("value");
        j.submit(p.getFormByName("config"));

        wc.goTo("logout");
        wc.login("foo");

        p = wc.goTo("configure");
        String crumb2 = p.getElementByName("Jenkins-Crumb").getAttribute("value");
        j.submit(p.getFormByName("config"));

        assertEquals(crumb1.equals(crumb2), areEqual);

        replaceAllCrumbInPageBy(p, crumb1);
        if (areEqual) {
            j.submit(p.getFormByName("config"));
        } else {
            try {
                // submit the form with foo crumb
                j.submit(p.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                WebResponse response = e.getResponse();
                String responseBody = response.getContentAsString();
                assertTrue(responseBody.contains("No valid crumb"));
            }
        }
    }

    @Test
    public void setupCrumbIssuerInWebUI() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        j.jenkins.setCrumbIssuer(createStrict(Options.NOTHING()));

        User.getById("foo", true);

        JenkinsRule.WebClient wc = j.createWebClient();
        wc.login("foo");

        configureIssuerUsingWebUI(wc, true, null, null, null, null, null);
        assertEquals(true, currentIssuer().isCheckClientIP());
        configureIssuerUsingWebUI(wc, false, null, null, null, null, null);
        assertEquals(false, currentIssuer().isCheckClientIP());

        configureIssuerUsingWebUI(wc, null, true, null, null, null, null);
        assertEquals(true, currentIssuer().isCheckSameSource());
        configureIssuerUsingWebUI(wc, null, false, null, null, null, null);
        assertEquals(false, currentIssuer().isCheckSameSource());

        configureIssuerUsingWebUI(wc, null, null, true, null, null, null);
        assertEquals(true, currentIssuer().isCheckOnlyLocalPath());
        configureIssuerUsingWebUI(wc, null, null, false, null, null, null);
        assertEquals(false, currentIssuer().isCheckOnlyLocalPath());

        configureIssuerUsingWebUI(wc, null, null, null, true, null, null);
        assertEquals(true, currentIssuer().isCheckSessionMatch());
        configureIssuerUsingWebUI(wc, null, null, null, false, null, null);
        assertEquals(false, currentIssuer().isCheckSessionMatch());

        configureIssuerUsingWebUI(wc, null, null, null, null, null, true);
        assertEquals(true, currentIssuer().isXorMasking());
        configureIssuerUsingWebUI(wc, null, null, null, null, null, false);
        assertEquals(false, currentIssuer().isXorMasking());

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

    private StrictCrumbIssuer currentIssuer(){
        return (StrictCrumbIssuer) j.jenkins.getCrumbIssuer();
    }

    private void configureIssuerUsingWebUI(
            JenkinsRule.WebClient wc,
            Boolean checkClientIP,
            Boolean checkSameSource,
            Boolean checkOnlyLocalPath,
            Boolean checkSessionMatch,
            Integer hoursValid,
            Boolean xorMasking
    ) throws Exception {
        HtmlPage p = wc.goTo("configureSecurity");
        HtmlForm form = p.getFormByName("config");
        if(checkClientIP != null){
            form.getInputByName("_.checkClientIP").setChecked(checkClientIP);
        }
        if(checkSameSource != null){
            form.getInputByName("_.checkSameSource").setChecked(checkSameSource);
        }
        if(checkOnlyLocalPath != null){
            form.getInputByName("_.checkOnlyLocalPath").setChecked(checkOnlyLocalPath);
        }
        if(checkSessionMatch != null){
            form.getInputByName("_.checkSessionMatch").setChecked(checkSessionMatch);
        }
        if(hoursValid != null){
            form.getInputByName("_.hoursValid").setValueAttribute("" + hoursValid);
        }
        if(xorMasking != null){
            form.getInputByName("_.xorMasking").setChecked(xorMasking);
        }
        HtmlPage result = j.submit(form);
        assertEquals(200, result.getWebResponse().getStatusCode());
    }

    @Test
    @WithoutJenkins
    public void checkTheHourValidRange() {
        // common case
        assertEquals(createStrict(Options.NOTHING().withHoursValid(1)).getHoursValid(), 1);
        assertEquals(createStrict(Options.NOTHING().withHoursValid(12)).getHoursValid(), 12);
        assertEquals(createStrict(Options.NOTHING().withHoursValid(24)).getHoursValid(), 24);

        // out of boundaries
        assertEquals(createStrict(Options.NOTHING().withHoursValid(-1)).getHoursValid(), 0);
        assertEquals(createStrict(Options.NOTHING().withHoursValid(-10)).getHoursValid(), 0);
        assertEquals(createStrict(Options.NOTHING().withHoursValid(25)).getHoursValid(), 24);
        assertEquals(createStrict(Options.NOTHING().withHoursValid(15235)).getHoursValid(), 24);
    }

    @Test
    @WithoutJenkins
    public void checkXorCorrect() throws Exception {
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
                options.xorMasking
        );
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
