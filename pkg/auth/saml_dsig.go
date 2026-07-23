// SAML XML-DSIG verification for the PQC auth gateway.
//
// IssueFromSAML now fails closed unless the caller has configured a trust
// store via PQCAuthGateway.SetSAMLTrustAnchors. Every assertion must carry a
// valid enveloped XML-DSIG signature (over the <Response> or the inner
// <Assertion>) that chains to one of the configured IdP signing certificates.
//
// This mitigates:
//   - Unsigned assertions being accepted verbatim.
//   - XML Signature Wrapping (XSW): only the element that goxmldsig actually
//     validated is used downstream — never the surrounding, untrusted DOM.
package auth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"strings"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// samlVerifier holds the configured SAML XML-DSIG validator plus the
// certificate store it was built from. A nil samlVerifier means SAML issuance
// is disabled — IssueFromSAML will fail closed.
type samlVerifier struct {
	mu    sync.RWMutex
	store *dsig.MemoryX509CertificateStore
	ctx   *dsig.ValidationContext
}

// newSAMLVerifier builds a validation context from the given trust anchors.
// Returns nil when certs is empty (feature disabled).
func newSAMLVerifier(certs []*x509.Certificate) *samlVerifier {
	if len(certs) == 0 {
		return nil
	}
	store := &dsig.MemoryX509CertificateStore{Roots: append([]*x509.Certificate(nil), certs...)}
	ctx := dsig.NewDefaultValidationContext(store)
	return &samlVerifier{store: store, ctx: ctx}
}

// validate returns the single etree element whose enveloped XML-DSIG
// signature chains to one of the configured IdP certificates. If neither the
// document root nor the inner <Assertion> carries a valid signature the call
// fails closed.
func (v *samlVerifier) validate(assertionXML []byte) (*etree.Element, error) {
	if v == nil {
		return nil, errors.New("pqc-auth: SAML trust anchors not configured — refusing to issue token")
	}
	v.mu.RLock()
	ctx := v.ctx
	v.mu.RUnlock()
	if ctx == nil {
		return nil, errors.New("pqc-auth: SAML validation context unavailable")
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(assertionXML); err != nil {
		return nil, fmt.Errorf("pqc-auth: parse SAML XML: %w", err)
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("pqc-auth: SAML document has no root element")
	}

	// 1) Try validating the document root (typically <Response> or a
	//    standalone <Assertion>). goxmldsig returns the validated element
	//    with the <Signature> child removed, so we always use the returned
	//    element for downstream identity extraction — never the raw DOM.
	if validated, err := ctx.Validate(root); err == nil {
		if el := selectAssertion(validated); el != nil {
			return el, nil
		}
		return validated, nil
	} else if !errors.Is(err, dsig.ErrMissingSignature) {
		return nil, fmt.Errorf("pqc-auth: SAML signature verification failed: %w", err)
	}

	// 2) Root is unsigned. Try validating the first <Assertion> child.
	inner := selectAssertion(root)
	if inner == nil {
		return nil, errors.New("pqc-auth: SAML assertion is not signed and no signed <Assertion> child was found")
	}
	validated, err := ctx.Validate(inner)
	if err != nil {
		if errors.Is(err, dsig.ErrMissingSignature) {
			return nil, errors.New("pqc-auth: SAML assertion is missing an XML-DSIG signature")
		}
		return nil, fmt.Errorf("pqc-auth: SAML assertion signature verification failed: %w", err)
	}
	return validated, nil
}

// selectAssertion returns the first descendant <Assertion> element (in any
// namespace) reachable from el, or nil if none exists.
func selectAssertion(el *etree.Element) *etree.Element {
	if el == nil {
		return nil
	}
	if el.Tag == "Assertion" {
		return el
	}
	for _, child := range el.FindElements(".//Assertion") {
		return child
	}
	return nil
}

// SetSAMLTrustAnchors installs (or replaces) the set of IdP signing
// certificates used to verify SAML assertions passed to IssueFromSAML.
// Passing an empty slice disables SAML issuance — IssueFromSAML will fail
// closed for every subsequent call. This is intentional: SAML MUST NOT be
// accepted without a configured trust store.
func (g *PQCAuthGateway) SetSAMLTrustAnchors(certs []*x509.Certificate) {
	next := newSAMLVerifier(certs)
	g.samlMu.Lock()
	g.samlVerifier = next
	g.samlMu.Unlock()
}

// samlValidator returns the current verifier under the gateway's read lock.
func (g *PQCAuthGateway) samlValidator() *samlVerifier {
	g.samlMu.RLock()
	defer g.samlMu.RUnlock()
	return g.samlVerifier
}

// extractSAMLIdentity walks a signature-validated <Assertion> element and
// returns the NameID and any role/group/memberOf attribute values. Only the
// element passed here (which goxmldsig has certified) is inspected.
func extractSAMLIdentity(assertion *etree.Element) (string, []string) {
	if assertion == nil {
		return "", nil
	}
	// The validated element may still be a <Response>; drill down to the
	// nested <Assertion> if so.
	if assertion.Tag != "Assertion" {
		if inner := selectAssertion(assertion); inner != nil {
			assertion = inner
		}
	}

	var subject string
	if el := assertion.FindElement("./Subject/NameID"); el != nil {
		subject = strings.TrimSpace(el.Text())
	}

	var roles []string
	for _, attr := range assertion.FindElements("./AttributeStatement/Attribute") {
		nameAttr := attr.SelectAttr("Name")
		if nameAttr == nil {
			continue
		}
		lower := strings.ToLower(nameAttr.Value)
		if !(strings.Contains(lower, "role") ||
			strings.Contains(lower, "group") ||
			strings.Contains(lower, "memberof")) {
			continue
		}
		for _, v := range attr.FindElements("./AttributeValue") {
			if txt := strings.TrimSpace(v.Text()); txt != "" {
				roles = append(roles, txt)
			}
		}
	}
	return subject, roles
}
