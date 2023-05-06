/*
 * The MIT License
 *
 * Copyright (c) 2018-2023, CloudBees, Inc.
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

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.RestrictedSince;
import hudson.Util;
import hudson.model.ModelObject;
import hudson.security.csrf.CrumbIssuer;
import hudson.security.csrf.CrumbIssuerDescriptor;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.annotation.PostConstruct;
import javax.annotation.concurrent.GuardedBy;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import jenkins.model.Jenkins;
import jenkins.security.HexStringConfidentialKey;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.security.core.Authentication;

public class StrictCrumbIssuer extends CrumbIssuer {

    static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String HEADER_REFERER = "Referer";

    private static final int MAX_HOURS_VALID = 24;
    private static final int TEMPORAL_VALIDATION_DISABLED = 0;

    private static final int MILLIS_PER_HOUR = 3600000;
    private static final int INCREMENTS_PER_HOUR = 12;

    private static final String MD_NAME = "SHA-256";
    private static final int MD_LENGTH = 64;

    private static final SecureRandom RANDOM = new SecureRandom();

    @GuardedBy("this")
    private transient MessageDigest md;

    /**
     * Compare X-Forwarded-For header
     */
    private boolean checkClientIP;

    /**
     * Compare the page where the token was issued with the request that is made with it after that.<br/>
     * The scope of the check is determined by {@link #checkOnlyLocalPath}
     */
    private boolean checkSameSource;

    /**
     * Determine if we check only the local path (all the right parts after the context path) or
     * the full url. <br/>
     * In any case the query parameters is also checked.<br/>
     * Only relevant if the {@link #checkSameSource} is {@code true}
     */
    private boolean checkOnlyLocalPath;

    /**
     * Check the session ID between when the crumb is issued and when used.
     * Meaning if the user disconnects, the token is automatically invalidated.
     */
    private boolean checkSessionMatch;

    /**
     * Determine if we add 32 random values (=seed) in front and xor them with the real crumb
     * [seed in clear][realCrumb ^ seed]
     * Prevent BREACH attack
     */
    private boolean xorMasking;

    /**
     * Value range from 0 to 24
     * Greater values are reduced to 24 and smaller increased to 0
     * 0 means no duration validation
     */
    @SuppressFBWarnings(value = "IS2_INCONSISTENT_SYNC", justification = "The synchronization is done for `md`")
    private int hoursValid;

    public StrictCrumbIssuer(
            boolean checkClientIP,
            boolean checkSameSource,
            boolean checkOnlyLocalPath,
            boolean checkSessionMatch,
            int hoursValid,
            boolean xorMasking) {

        this.checkClientIP = checkClientIP;
        this.checkSameSource = checkSameSource;
        this.checkOnlyLocalPath = checkOnlyLocalPath;
        this.checkSessionMatch = checkSessionMatch;
        this.hoursValid = hoursValid;
        this.xorMasking = xorMasking;

        this.ensureHoursValidIsInBoundaries();
        this.initMessageDigest();
    }

    @DataBoundConstructor
    public StrictCrumbIssuer() {
        this.checkClientIP = false;
        this.checkSameSource = false;
        this.checkOnlyLocalPath = false;
        this.checkSessionMatch = true;
        this.hoursValid = 2;
        this.xorMasking = true;
    }

    @DataBoundSetter
    public void setCheckClientIP(boolean checkClientIP) {
        this.checkClientIP = checkClientIP;
    }

    @DataBoundSetter
    public void setCheckSameSource(boolean checkSameSource) {
        this.checkSameSource = checkSameSource;
    }

    @DataBoundSetter
    public void setCheckOnlyLocalPath(boolean checkOnlyLocalPath) {
        this.checkOnlyLocalPath = checkOnlyLocalPath;
    }

    @DataBoundSetter
    public void setCheckSessionMatch(boolean checkSessionMatch) {
        this.checkSessionMatch = checkSessionMatch;
    }

    @DataBoundSetter
    public void setHoursValid(int hoursValid) {
        this.hoursValid = hoursValid;
    }

    @DataBoundSetter
    public void setXorMasking(boolean xorMasking) {
        this.xorMasking = xorMasking;
    }

    // only set public for JCasC as they do not currently support private methods for PostConstruct
    @Restricted(NoExternalUse.class)
    @PostConstruct
    public void setup() {
        this.ensureHoursValidIsInBoundaries();
        this.initMessageDigest();
    }

    private Object readResolve() {
        this.ensureHoursValidIsInBoundaries();
        this.initMessageDigest();

        return this;
    }

    private synchronized void initMessageDigest() {
        try {
            this.md = MessageDigest.getInstance(MD_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError("Can't find " + MD_NAME);
        }
    }

    private void ensureHoursValidIsInBoundaries() {
        // normally the UI prevent value outside of the boundaries,
        // but we must ensure no javascript manipulation is possible
        if (hoursValid > MAX_HOURS_VALID) {
            LOGGER.log(
                    Level.WARNING,
                    "The hoursValid (" + hoursValid + ") is too big, it will be reduced to " + MAX_HOURS_VALID);
            hoursValid = MAX_HOURS_VALID;
        } else if (hoursValid < TEMPORAL_VALIDATION_DISABLED) {
            LOGGER.log(
                    Level.WARNING,
                    "The hoursValid (" + hoursValid + ") is too small, the duration validation will be deactivated.");
            hoursValid = TEMPORAL_VALIDATION_DISABLED;
        }
    }

    /**
     * @deprecated name was changed for JCasC, please use isCheckClientIP instead
     */
    @Deprecated
    @RestrictedSince("2.1.0")
    @Restricted(NoExternalUse.class)
    public boolean isCheckingClientIP() {
        return this.checkClientIP;
    }

    /**
     * @deprecated name was changed for JCasC, please use isCheckSameSource instead
     */
    @Deprecated
    @RestrictedSince("2.1.0")
    @Restricted(NoExternalUse.class)
    public boolean isCheckingSameSource() {
        return this.checkSameSource;
    }

    /**
     * @deprecated name was changed for JCasC, please use isCheckOnlyLocalPath instead
     */
    @Deprecated
    @RestrictedSince("2.1.0")
    @Restricted(NoExternalUse.class)
    public boolean isCheckingOnlyLocalPath() {
        return this.checkOnlyLocalPath;
    }

    /**
     * @deprecated name was changed for JCasC, please use isCheckSessionMatch instead
     */
    @Deprecated
    @RestrictedSince("2.1.0")
    @Restricted(NoExternalUse.class)
    public boolean isCheckingSessionMatch() {
        return this.checkSessionMatch;
    }

    public boolean isCheckClientIP() {
        return this.checkClientIP;
    }

    public boolean isCheckSameSource() {
        return this.checkSameSource;
    }

    public boolean isCheckOnlyLocalPath() {
        return this.checkOnlyLocalPath;
    }

    public boolean isCheckSessionMatch() {
        return this.checkSessionMatch;
    }

    public int getHoursValid() {
        return this.hoursValid;
    }

    public boolean isXorMasking() {
        return this.xorMasking;
    }

    @Override
    protected synchronized @CheckForNull String issueCrumb(@Nonnull ServletRequest request, @Nonnull String salt) {
        if (request instanceof HttpServletRequest) {
            if (md != null) {
                HttpServletRequest req = (HttpServletRequest) request;
                String sourceUrl = urlForCreation(req);
                String crumb = createCrumb(request, salt, getCurrentHour(), sourceUrl);
                return encodeCrumb(crumb);
            }
        }
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized boolean validateCrumb(
            @Nonnull ServletRequest request, @Nonnull String salt, @CheckForNull String encodedCrumb) {
        if (request instanceof HttpServletRequest) {
            if (encodedCrumb != null) {
                String crumb = decodeCrumb(encodedCrumb);
                byte[] crumbBytes = crumb.getBytes(StandardCharsets.US_ASCII);

                HttpServletRequest req = (HttpServletRequest) request;
                String sourceUrl = urlForValidation(req);

                if (hoursValid == TEMPORAL_VALIDATION_DISABLED) {
                    if (isCrumbValid(request, salt, 0, crumbBytes, sourceUrl)) {
                        return true;
                    }
                } else {
                    long hours = getCurrentHour();
                    int numOfIncrements = INCREMENTS_PER_HOUR * getHoursValid();
                    for (int i = 0; i <= numOfIncrements; i++) {
                        if (isCrumbValid(request, salt, hours - i, crumbBytes, sourceUrl)) {
                            return true;
                        }
                    }
                }
                LOGGER.log(Level.INFO, "Invalid crumb found in the request");
            } else {
                LOGGER.log(Level.FINER, "No crumb available in the request");
            }
        } else {
            LOGGER.log(Level.WARNING, "Passed request not a HttpServletRequest");
        }
        return false;
    }

    private boolean isCrumbValid(
            @Nonnull ServletRequest request,
            @Nonnull String salt,
            long hours,
            @Nonnull byte[] actualCrumbBytes,
            @CheckForNull String sourceUrl) {
        String newCrumb = createCrumb(request, salt, hours, sourceUrl);

        // even if the crumb is hex string (currently), we use ASCII to avoid variable length encoding
        // (like UTF-8) that could give some information
        byte[] newCrumbBytes = newCrumb.getBytes(StandardCharsets.US_ASCII);

        // String.equals() is not constant-time, but this is
        if (MessageDigest.isEqual(newCrumbBytes, actualCrumbBytes)) {
            // shortcut should be fine as age of crumb is probably not a security concern
            return true;
        }

        return false;
    }

    long getCurrentHour() {
        return new Date().getTime() / (MILLIS_PER_HOUR / INCREMENTS_PER_HOUR);
    }

    private @CheckForNull String urlForCreation(@Nonnull HttpServletRequest req) {
        if (isCheckSameSource()) {
            if (isCheckOnlyLocalPath()) {
                String contextPath = req.getContextPath();
                String requestURI = req.getRequestURI();
                if (!requestURI.startsWith(contextPath)) {
                    LOGGER.log(Level.WARNING, "RequestURI {0} does not start with contextPath", requestURI);
                }

                String localPath = requestURI.substring(contextPath.length());
                String query = req.getQueryString();
                if (query != null) {
                    localPath += "?" + query;
                }

                return localPath;
            } else {
                String requestUrl = req.getRequestURL().toString();
                String query = req.getQueryString();

                String url = requestUrl;
                if (query != null) {
                    url += "?" + query;
                }

                return url;
            }
        } else {
            return null;
        }
    }

    private @CheckForNull String urlForValidation(@Nonnull HttpServletRequest req) {
        if (isCheckSameSource()) {
            String referer = req.getHeader(HEADER_REFERER);
            if (referer == null) {
                LOGGER.log(
                        Level.WARNING,
                        "No referer present in the request, perhaps it is better to check only local path");
                return null;
            }

            if (isCheckOnlyLocalPath()) {
                URL url;
                try {
                    url = new URL(referer);
                } catch (MalformedURLException e) {
                    LOGGER.log(Level.WARNING, "The referer value is not parseable as URL", e);
                    throw new RuntimeException(e);
                }
                String contextPath = req.getContextPath();
                String pathWithContext = url.getFile();

                if (!pathWithContext.startsWith(contextPath)) {
                    LOGGER.log(Level.WARNING, "Request path {0} does not start with contextPath", pathWithContext);
                    return null;
                }

                return pathWithContext.substring(contextPath.length());
            } else {
                return referer;
            }
        } else {
            return null;
        }
    }

    private synchronized @Nonnull String createCrumb(
            @Nonnull ServletRequest request, @Nonnull String salt, long creationTime, @CheckForNull String sourceUrl) {
        HttpServletRequest req = (HttpServletRequest) request;
        StringBuilder builder = new StringBuilder();

        Authentication a = Jenkins.getAuthentication2();
        builder.append(a.getName());
        builder.append(';');

        if (isCheckClientIP()) {
            builder.append(getClientIP(req));
            builder.append(';');
        }

        if (sourceUrl != null) {
            builder.append(sourceUrl);
            builder.append(';');
        }

        if (isCheckSessionMatch()) {
            builder.append(req.getSession().getId());
            builder.append(';');
        }

        if (hoursValid == TEMPORAL_VALIDATION_DISABLED) {
            builder.append("0");
        } else {
            builder.append(creationTime);
        }

        String clearCrumb = builder.toString();
        md.update(clearCrumb.getBytes(StandardCharsets.UTF_8));
        byte[] crumbBytes = md.digest(salt.getBytes(StandardCharsets.UTF_8));
        String hashedCrumb = Util.toHexString(crumbBytes);

        // 64 characters
        return hashedCrumb;
    }

    private @Nonnull String randomHexString(int length) {
        // bytes => hex conversion will be multiplied by 2
        byte[] bytes = new byte[length / 2];

        RANDOM.nextBytes(bytes);
        return Util.toHexString(bytes);
    }

    private String getClientIP(@Nonnull HttpServletRequest req) {
        String defaultAddress = req.getRemoteAddr();
        String forwarded = req.getHeader(HEADER_X_FORWARDED_FOR);
        if (forwarded != null) {
            String[] hopList = forwarded.split(",");
            if (hopList.length >= 1) {
                return hopList[0];
            }
        }
        return defaultAddress;
    }

    private @Nonnull String encodeCrumb(@Nonnull String clearCrumb) {
        String seed;
        String encodedCrumb;
        if (isXorMasking()) {
            seed = randomHexString(clearCrumb.length());
            encodedCrumb = xor(clearCrumb, seed);
        } else {
            seed = "";
            encodedCrumb = clearCrumb;
        }

        return seed + encodedCrumb;
    }

    private @Nonnull String decodeCrumb(@Nonnull String receivedCrumb) {
        String realCrumb;
        if (isXorMasking()) {
            realCrumb = unXor(receivedCrumb);
        } else {
            realCrumb = receivedCrumb;
        }

        return realCrumb;
    }

    private @Nonnull String unXor(@Nonnull String crumbDoubleLength) {
        if (crumbDoubleLength.length() != 2 * MD_LENGTH) {
            return "";
        }

        String seed = crumbDoubleLength.substring(0, MD_LENGTH);
        String xoredCrumb = crumbDoubleLength.substring(MD_LENGTH, 2 * MD_LENGTH);
        return xor(xoredCrumb, seed);
    }

    private @Nonnull String xor(@Nonnull String realCrumb, @Nonnull String seedOfSameLength) {
        assert realCrumb.length() == seedOfSameLength.length();

        BigInteger hexCrumb = new BigInteger(realCrumb, 16);
        BigInteger hexSeed = new BigInteger(seedOfSameLength, 16);
        BigInteger hexResult = hexCrumb.xor(hexSeed);
        String stringResult = hexResult.toString(16);

        // in case the crumb starts with 0's, we need to put them back
        return leftPadWithZeros(stringResult, realCrumb.length());
    }

    @SuppressFBWarnings(
            value = "NP_NONNULL_RETURN_VIOLATION",
            justification = "leftPad returns null only if receiving null, which is not the case here")
    private static @Nonnull String leftPadWithZeros(@Nonnull String stringToBePadded, int length) {
        return StringUtils.leftPad(stringToBePadded, length, '0');
    }

    @Extension
    @Symbol("strict")
    public static final class DescriptorImpl extends CrumbIssuerDescriptor<StrictCrumbIssuer> implements ModelObject {
        private static final HexStringConfidentialKey CRUMB_SALT =
                new HexStringConfidentialKey(StrictCrumbIssuer.class, "strictCrumbSalt", 64);

        public DescriptorImpl() {
            super(
                    CRUMB_SALT.get(),
                    System.getProperty("hudson.security.csrf.requestfield", CrumbIssuer.DEFAULT_CRUMB_NAME));
            load();
        }

        @Override
        public String getDisplayName() {
            return "Strict Crumb Issuer"; /* TODO i18n */
        }

        @Override
        public StrictCrumbIssuer newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            if (req == null) {
                throw new IllegalArgumentException("req must not be null");
            }
            return req.bindJSON(StrictCrumbIssuer.class, formData);
        }
    }

    private static final Logger LOGGER = Logger.getLogger(StrictCrumbIssuer.class.getName());
}
