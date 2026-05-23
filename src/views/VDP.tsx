import { Helmet } from "react-helmet";
import { Link } from '@/lib/router-compat';
import { Shield, Mail, Award, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";

const VDP = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-background via-background/95 to-secondary/20">
      <Helmet>
        <title>Vulnerability Disclosure Program | NouchiX Security</title>
        <meta name="description" content="NouchiX welcomes responsible security research. Learn how to report vulnerabilities and help make critical infrastructure safer." />
        <meta name="keywords" content="vulnerability disclosure, bug bounty, security research, responsible disclosure, VDP" />
        <link rel="canonical" href="https://souhimbou.ai/vdp" />
      </Helmet>

      <div className="container mx-auto px-4 py-12 max-w-4xl">
        <Link to="/" className="inline-flex items-center text-primary hover:text-primary/80 transition-colors mb-8">
          ← Back to Home
        </Link>

        <div className="space-y-12">
          {/* Header */}
          <header className="text-center space-y-4">
            <div className="flex justify-center">
              <Shield className="w-16 h-16 text-primary" />
            </div>
            <h1 className="text-4xl md:text-5xl font-bold">
              Vulnerability Disclosure Program
            </h1>
            <p className="text-xl text-muted-foreground italic">
              Help us build resilient systems for critical infrastructure
            </p>
          </header>

          {/* Quick Summary */}
          <section className="bg-card border border-border rounded-lg p-8 space-y-4">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              🛡️ Welcome Security Researchers
            </h2>
            <p className="text-lg leading-relaxed">
              NouchiX welcomes responsible security research. If you find a vulnerability in our systems, 
              please disclose it responsibly — we'll review and work to fix it, and we'll credit contributors 
              publicly unless they ask us not to.
            </p>
            <div className="flex items-center gap-2 text-primary font-semibold">
              <Mail className="w-5 h-5" />
              <span>security@secredknowledgeinc.tech</span>
            </div>
            <p className="text-sm text-muted-foreground">
              Thank you for helping make critical infrastructure safer.
            </p>
          </section>

          {/* Scope */}
          <section className="space-y-6">
            <h2 className="text-3xl font-bold flex items-center gap-2">
              🎯 Scope
            </h2>
            
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-card border border-green-500/20 rounded-lg p-6 space-y-4">
                <h3 className="text-xl font-bold flex items-center gap-2 text-green-600 dark:text-green-400">
                  <CheckCircle2 className="w-6 h-6" />
                  In Scope
                </h3>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <span className="text-green-600 dark:text-green-400">✓</span>
                    <span>Production web applications (souhimbou.ai, secredknowledgeinc.tech)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-green-600 dark:text-green-400">✓</span>
                    <span>Public APIs and demo endpoints</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-green-600 dark:text-green-400">✓</span>
                    <span>Public GitHub repositories we maintain</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-green-600 dark:text-green-400">✓</span>
                    <span>Open documentation and CI/CD metadata</span>
                  </li>
                </ul>
              </div>

              <div className="bg-card border border-red-500/20 rounded-lg p-6 space-y-4">
                <h3 className="text-xl font-bold flex items-center gap-2 text-red-600 dark:text-red-400">
                  <XCircle className="w-6 h-6" />
                  Out of Scope
                </h3>
                <ul className="space-y-2 text-sm">
                  <li className="flex items-start gap-2">
                    <span className="text-red-600 dark:text-red-400">✗</span>
                    <span>Social engineering or phishing</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-600 dark:text-red-400">✗</span>
                    <span>Physical attacks on facilities/devices</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-600 dark:text-red-400">✗</span>
                    <span>Denial of Service (DoS) attacks</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-red-600 dark:text-red-400">✗</span>
                    <span>Customer data access or exfiltration</span>
                  </li>
                </ul>
              </div>
            </div>
          </section>

          {/* Safe Harbor */}
          <section className="bg-card border border-border rounded-lg p-8 space-y-4">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              🤝 Safe Harbor Statement
            </h2>
            <p className="leading-relaxed">
              If you follow this VDP and make a good-faith effort to avoid privacy violation, data exfiltration, 
              or service disruption, NouchiX will not pursue legal action against you for the disclosed activity. 
              We do not authorize exploitation of customer data, privileged accounts, or destructive actions. 
              This safe-harbor applies only to researchers acting in good faith and per our program rules.
            </p>
          </section>

          {/* How to Report */}
          <section className="space-y-6">
            <h2 className="text-3xl font-bold flex items-center gap-2">
              📝 How to Report a Vulnerability
            </h2>
            
            <div className="bg-card border border-border rounded-lg p-8 space-y-4">
              <p className="font-semibold">Subject: VDP Submission — [short title] — [Critical/High/Medium/Low] — [target host]</p>
              
              <div className="space-y-3 text-sm">
                <p className="font-semibold">Required Information:</p>
                <ol className="space-y-2 list-decimal list-inside">
                  <li><strong>Researcher name/handle</strong> and contact email (or anonymous if preferred)</li>
                  <li><strong>Target</strong> (domain, service, API, URL)</li>
                  <li><strong>Vulnerability type</strong> (e.g., SQLi, XSS, misconfiguration)</li>
                  <li><strong>Steps to reproduce</strong> (concise, numbered) — include commands, URLs, sample payloads</li>
                  <li><strong>Proof of concept</strong> — screenshots, curl output, safe sample logs (redact sensitive data)</li>
                  <li><strong>Impact assessment</strong> — your view of risk and who is affected</li>
                  <li><strong>Suggested remediation</strong> (if any)</li>
                  <li><strong>Disclosure preference</strong> — public credit / anonymous / private</li>
                  <li><strong>Optional:</strong> PGP key or public SSH key for secure replies</li>
                </ol>
                
                <p className="text-muted-foreground mt-4">
                  <strong>Attachments:</strong> Single ZIP (password-protected) or PGP-signed message recommended.
                </p>
              </div>
            </div>
          </section>

          {/* Recognition */}
          <section className="bg-gradient-to-r from-primary/10 to-secondary/10 border border-border rounded-lg p-8 space-y-6">
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <Award className="w-8 h-8 text-primary" />
              Recognition & Rewards
            </h2>
            
            <p className="text-muted-foreground">We offer non-monetary recognition for responsible researchers:</p>
            
            <ul className="space-y-3">
              <li className="flex items-start gap-3">
                <span className="text-2xl">🏆</span>
                <div>
                  <strong>Hall of Fame</strong> — Featured on our website with your preferred credit
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-2xl">🎖️</span>
                <div>
                  <strong>GitHub Contributor Badge</strong> — Credit in public repos and releases
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-2xl">📢</span>
                <div>
                  <strong>Public Recognition</strong> — LinkedIn shoutout or tweet from SouHimBou (opt-in)
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-2xl">🚀</span>
                <div>
                  <strong>Early Access</strong> — Beta features in non-production environments
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="text-2xl">👥</span>
                <div>
                  <strong>Community Access</strong> — Private research channel for trusted researchers
                </div>
              </li>
            </ul>

            <Link 
              to="/hall-of-fame" 
              className="inline-block bg-primary text-primary-foreground px-6 py-3 rounded-lg font-semibold hover:bg-primary/90 transition-colors"
            >
              View Hall of Fame →
            </Link>
          </section>

          {/* Severity Levels */}
          <section className="space-y-6">
            <h2 className="text-3xl font-bold flex items-center gap-2">
              <AlertTriangle className="w-8 h-8" />
              Severity Levels
            </h2>
            
            <div className="grid gap-4">
              <div className="bg-card border-l-4 border-l-red-500 p-4">
                <h3 className="font-bold text-red-600 dark:text-red-400">Critical</h3>
                <p className="text-sm text-muted-foreground">Remote code execution, credentials exfiltration, active compromise of customer data, control of OT/ICS components</p>
              </div>
              <div className="bg-card border-l-4 border-l-orange-500 p-4">
                <h3 className="font-bold text-orange-600 dark:text-orange-400">High</h3>
                <p className="text-sm text-muted-foreground">Auth bypass, privilege escalation, severe config flaw exposing sensitive data</p>
              </div>
              <div className="bg-card border-l-4 border-l-yellow-500 p-4">
                <h3 className="font-bold text-yellow-600 dark:text-yellow-400">Medium</h3>
                <p className="text-sm text-muted-foreground">Information disclosure, XSS with limited impact, SSRF with mitigations</p>
              </div>
              <div className="bg-card border-l-4 border-l-blue-500 p-4">
                <h3 className="font-bold text-blue-600 dark:text-blue-400">Low</h3>
                <p className="text-sm text-muted-foreground">UI bugs, minor misconfigurations, best-practice issues</p>
              </div>
            </div>
          </section>

          {/* Process */}
          <section className="bg-card border border-border rounded-lg p-8 space-y-6">
            <h2 className="text-2xl font-bold">🔄 Our Process</h2>
            
            <ol className="space-y-4">
              <li className="flex items-start gap-3">
                <span className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">1</span>
                <div>
                  <strong>Acknowledge</strong> receipt promptly
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">2</span>
                <div>
                  <strong>Triage</strong> severity and assign owner
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">3</span>
                <div>
                  <strong>Patch/Mitigate</strong> (or create compensating control)
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">4</span>
                <div>
                  <strong>Validate</strong> fix with reporter (if they choose)
                </div>
              </li>
              <li className="flex items-start gap-3">
                <span className="flex-shrink-0 w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center font-bold">5</span>
                <div>
                  <strong>Close</strong> with public credit statement (if reporter opts in)
                </div>
              </li>
            </ol>
          </section>

          {/* Contact */}
          <section className="text-center bg-gradient-to-r from-primary/5 to-secondary/5 border border-border rounded-lg p-8 space-y-4">
            <h2 className="text-2xl font-bold">📞 Contact Us</h2>
            <div className="space-y-2">
              <p><strong>Primary:</strong> security@secredknowledgeinc.tech</p>
              <p><strong>Alternate:</strong> cybersouhimbou@secredknowledgeinc.tech</p>
              <p><strong>Website:</strong> <a href="https://souhimbou.ai" className="text-primary hover:underline">souhimbou.ai</a></p>
            </div>
            <p className="text-sm text-muted-foreground italic pt-4">
              This program is part of our Building In Public commitment to transparency and community-driven security.
            </p>
          </section>
        </div>
      </div>
    </div>
  );
};

export default VDP;
