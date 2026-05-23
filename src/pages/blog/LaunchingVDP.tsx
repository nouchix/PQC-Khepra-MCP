import { Helmet } from "react-helmet";
import { Link } from '@/lib/router-compat';

const LaunchingVDP = () => {
  return (
    <div className="min-h-screen bg-gradient-to-b from-background via-background/95 to-secondary/20">
      <Helmet>
        <title>Launching Our Vulnerability Disclosure Program | SouHimBou AI Blog</title>
        <meta name="description" content="We're launching a public Vulnerability Disclosure Program — NouchiX welcomes responsible researchers to help us build resilient systems for critical infrastructure." />
        <meta name="keywords" content="vulnerability disclosure program, VDP, bug bounty, security research, building in public, responsible disclosure" />
        <link rel="canonical" href="https://souhimbou.ai/blog/launching-vdp" />
      </Helmet>

      <div className="container mx-auto px-4 py-12 max-w-3xl">
        <Link to="/blog" className="inline-flex items-center text-primary hover:text-primary/80 transition-colors mb-8">
          ← Back to Blog
        </Link>

        <article className="bg-card border border-border rounded-lg p-8 md:p-12 space-y-8">
          {/* Header */}
          <header className="space-y-4">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <span className="px-3 py-1 bg-primary/10 text-primary rounded-full font-medium">
                Building In Public
              </span>
              <span>•</span>
              <time dateTime="2025-01-26">January 26, 2025</time>
              <span>•</span>
              <span>6 min read</span>
            </div>

            <h1 className="text-4xl md:text-5xl font-bold leading-tight">
              🛡️ Launching Our Vulnerability Disclosure Program
            </h1>

            <p className="text-xl text-muted-foreground italic leading-relaxed">
              Inviting the security community to help us build resilient systems for critical infrastructure — together.
            </p>
          </header>

          {/* Main Content */}
          <div className="prose prose-lg dark:prose-invert max-w-none space-y-6">
            <blockquote className="border-l-4 border-primary pl-6 italic text-lg">
              "Security is not a product, but a process — and that process works best when it's collaborative, 
              transparent, and community-driven."
            </blockquote>

            <h2 className="text-2xl font-bold mt-8">🚀 Why We're Doing This</h2>
            
            <p>
              Today marks an important milestone in our Building In Public journey: we're officially launching 
              the <strong>NouchiX Vulnerability Disclosure Program (VDP)</strong>.
            </p>

            <p>
              As we build SouHimBou AI — a platform designed to bring cyber resilience to critical infrastructure — 
              we recognize that security cannot be achieved in isolation. The most secure systems are those that 
              have been tested, challenged, and hardened by a diverse community of researchers, practitioners, 
              and ethical hackers.
            </p>

            <p>
              This VDP is our formal invitation to security researchers worldwide: <strong>help us find vulnerabilities 
              before adversaries do</strong>.
            </p>

            <h2 className="text-2xl font-bold mt-8">🤝 What Makes Our VDP Different</h2>

            <p>
              Our program embodies three core principles:
            </p>

            <ul className="space-y-3 my-6">
              <li>
                <strong>🌍 Transparency First</strong> — As part of our Building In Public ethos, we're open about 
                our security posture, our process, and our progress. When researchers help us improve, we want the 
                world to know.
              </li>
              <li>
                <strong>💰 Recognition Over Rewards</strong> — We're a bootstrap operation building critical 
                infrastructure resilience. Instead of bounties, we offer genuine recognition: Hall of Fame placement, 
                public credit, early access to features, and invitations to our research community.
              </li>
              <li>
                <strong>⚖️ Safe Harbor</strong> — We provide clear legal safe-harbor for good-faith researchers. 
                If you follow our rules and report responsibly, we won't pursue legal action — period.
              </li>
            </ul>

            <h2 className="text-2xl font-bold mt-8">📋 What's In Scope?</h2>

            <p>
              We're inviting researchers to test:
            </p>

            <ul className="space-y-2 my-6">
              <li>✅ Our production web applications (souhimbou.ai, secredknowledgeinc.tech)</li>
              <li>✅ Public APIs and demo endpoints we publish</li>
              <li>✅ Our open-source repositories and research materials</li>
              <li>✅ Publicly exposed documentation and CI/CD metadata</li>
            </ul>

            <p>
              What's <strong>not</strong> in scope? Social engineering, phishing, DoS attacks, or anything that 
              would compromise customer data or disrupt services. We want collaborative security research, 
              not adversarial testing.
            </p>

            <h2 className="text-2xl font-bold mt-8">🏆 How We'll Recognize Contributors</h2>

            <p>
              Every researcher who responsibly discloses a valid vulnerability will receive:
            </p>

            <ul className="space-y-3 my-6">
              <li>
                <strong>🏆 Hall of Fame Recognition</strong> — Featured on our public Hall of Fame page 
                (unless you prefer anonymity)
              </li>
              <li>
                <strong>🎖️ GitHub Credit</strong> — Contributor badge and recognition in our release notes
              </li>
              <li>
                <strong>📢 Public Shoutouts</strong> — LinkedIn posts and tweets from SouHimBou (opt-in)
              </li>
              <li>
                <strong>🚀 Early Access</strong> — Beta features and invites to our private research community
              </li>
            </ul>

            <h2 className="text-2xl font-bold mt-8">📨 How to Report</h2>

            <p>
              If you find something, here's what we need:
            </p>

            <ol className="space-y-2 my-6">
              <li><strong>1.</strong> Your contact info (or anonymous, if you prefer)</li>
              <li><strong>2.</strong> The target system and vulnerability type</li>
              <li><strong>3.</strong> Step-by-step reproduction instructions</li>
              <li><strong>4.</strong> Proof of concept (screenshots, logs, safe payloads)</li>
              <li><strong>5.</strong> Your assessment of impact and risk</li>
              <li><strong>6.</strong> Your disclosure preference (public credit or anonymous)</li>
            </ol>

            <p>
              Send everything to: <strong className="text-primary">security@secredknowledgeinc.tech</strong> or 
              <strong className="text-primary"> cybersouhimbou@secredknowledgeinc.tech</strong>
            </p>

            <p className="text-sm text-muted-foreground italic">
              Pro tip: Password-protect your PoC attachments or use PGP encryption — we'll provide keys on request.
            </p>

            <h2 className="text-2xl font-bold mt-8">🔄 Our Response Process</h2>

            <p>
              When you submit a report, here's what happens:
            </p>

            <ul className="space-y-2 my-6">
              <li><strong>Acknowledge</strong> — We'll confirm receipt promptly</li>
              <li><strong>Triage</strong> — We'll assess severity and assign an owner</li>
              <li><strong>Fix</strong> — We'll patch the issue or implement mitigations</li>
              <li><strong>Validate</strong> — We'll work with you to confirm the fix (if you want)</li>
              <li><strong>Recognize</strong> — We'll credit you publicly (if you opt in)</li>
            </ul>

            <p>
              We won't publish hard SLAs yet (we're still early-stage), but we commit to prompt acknowledgment 
              and transparent communication throughout the process.
            </p>

            <h2 className="text-2xl font-bold mt-8">💭 A Personal Note from NouchiX</h2>

            <p>
              Building SouHimBou AI has been a journey of learning, iteration, and radical transparency. 
              This VDP is the natural extension of that philosophy: <strong>we can't secure critical infrastructure 
              alone</strong>.
            </p>

            <p>
              Whether you're a seasoned security researcher, a curious student, or a practitioner who stumbles 
              on something unusual — we want to hear from you. Your findings make us better. Your feedback makes 
              our systems more resilient. Your participation makes critical infrastructure safer.
            </p>

            <p>
              Thank you for being part of this journey.
            </p>

            <h2 className="text-2xl font-bold mt-8">🔗 Take Action</h2>

            <div className="bg-primary/5 border border-primary/20 rounded-lg p-6 space-y-4">
              <p className="font-semibold">Ready to contribute?</p>
              <ul className="space-y-2">
                <li>
                  <Link to="/vdp" className="text-primary hover:underline font-medium">
                    → Read the full Vulnerability Disclosure Program
                  </Link>
                </li>
                <li>
                  <Link to="/hall-of-fame" className="text-primary hover:underline font-medium">
                    → Check out our Hall of Fame (be the first!)
                  </Link>
                </li>
                <li>
                  <a 
                    href="https://github.com/souhimbou" 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-primary hover:underline font-medium"
                  >
                    → Explore our public repositories
                  </a>
                </li>
              </ul>
            </div>

            <h2 className="text-2xl font-bold mt-8">🌍 Let's Build Together</h2>

            <p>
              Security research isn't just about finding bugs — it's about building trust, fostering collaboration, 
              and making the digital infrastructure that powers our world more resilient.
            </p>

            <p className="font-semibold">
              If you find something, report it. If you have questions, ask. If you want to help, reach out.
            </p>

            <p>
              Together, we're building cyber immunity in public.
            </p>
          </div>

          {/* Footer */}
          <footer className="border-t border-border pt-8 space-y-6">
            <div className="flex items-center gap-4">
              <img 
                src="/lovable-uploads/4d5b7c98-b893-4c8f-832e-d98c4f24ac88.png" 
                alt="NouchiX" 
                className="w-16 h-16 rounded-full"
              />
              <div>
                <p className="font-bold">NouchiX (Jean Derlin Kue)</p>
                <p className="text-sm text-muted-foreground">Founder & Chief Architect, SouHimBou AI</p>
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-sm text-muted-foreground">
                Building cyber resilience for critical infrastructure • One system at a time • In public
              </p>
              <div className="flex gap-4 text-sm">
                <a 
                  href="https://www.linkedin.com/in/jean-derlin-kue/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  LinkedIn
                </a>
                <span className="text-muted-foreground">•</span>
                <a 
                  href="https://github.com/souhimbou" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="text-primary hover:underline"
                >
                  GitHub
                </a>
                <span className="text-muted-foreground">•</span>
                <a 
                  href="mailto:cybersouhimbou@secredknowledgeinc.tech"
                  className="text-primary hover:underline"
                >
                  Email
                </a>
              </div>
            </div>
          </footer>
        </article>
      </div>
    </div>
  );
};

export default LaunchingVDP;
