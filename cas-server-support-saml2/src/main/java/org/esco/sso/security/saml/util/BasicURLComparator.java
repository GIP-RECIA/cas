package org.esco.sso.security.saml.util;

import org.opensaml.common.binding.decoding.URIComparator;
import org.opensaml.util.SimpleURLCanonicalizer;

/**
 * Override original class to remove parameters from url !
 * A basic implementation of {@link URIComparator} that compares
 * URL's by canonicalizing them as per {@link SimpleURLCanonicalizer},
 * and then compares the resulting string representations for equality
 * using String equals(). If {link {@link #isCaseInsensitive()} is true,
 * then the equality test is instead performed using String equalsIgnoreCase().
 */
public class BasicURLComparator implements URIComparator {

    /** The case-insensitivity flag. */
    private boolean caseInsensitive;

    /**
     * Get the case-insensitivity flag value.
     * @return Returns the caseInsensitive.
     */
    public boolean isCaseInsensitive() {
        return caseInsensitive;
    }

    /**
     * Set the case-insensitivity flag value.
     * @param flag The caseInsensitive to set.
     */
    public void setCaseInsensitive(boolean flag) {
        caseInsensitive = flag;
    }

    /** {@inheritDoc} */
    public boolean compare(String uri1, String uri2) {
        if (uri1 == null) {
            return uri2 == null;
        } else if (uri2 == null) {
            return uri1 == null;
        } else {
            String uri1Canon = SimpleURLCanonicalizer.canonicalize(uri1);
            uri1Canon = uri1Canon.split("\\?")[0];
            String uri2Canon = SimpleURLCanonicalizer.canonicalize(uri2);
            uri2Canon = uri2Canon.split("\\?")[0];
            if (isCaseInsensitive()) {
                return uri1Canon.equalsIgnoreCase(uri2Canon);
            } else {
                return uri1Canon.equals(uri2Canon);
            }
        }
    }

}
