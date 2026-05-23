import { Helmet } from "react-helmet";
import { Link } from '@/lib/router-compat';
import { Trophy, Shield, Star } from "lucide-react";

const HallOfFame = () => {
  // This will be populated as researchers contribute
  const researchers = [
    // Example format (to be added as contributions come in):
    // {
    //   name: "John Doe",
    //   handle: "@johndoe",
    //   date: "2025-01",
    //   severity: "High",
    //   description: "Discovered authentication bypass vulnerability",
    //   anonymous: false
    // }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-b from-background via-background/95 to-secondary/20">
      <Helmet>
        <title>Security Hall of Fame | NouchiX</title>
        <meta name="description" content="Recognizing security researchers who have helped make NouchiX more secure through responsible disclosure." />
        <meta name="keywords" content="security researchers, hall of fame, responsible disclosure, bug bounty recognition" />
        <link rel="canonical" href="https://souhimbou.ai/hall-of-fame" />
      </Helmet>

      <div className="container mx-auto px-4 py-12 max-w-4xl">
        <Link to="/vdp" className="inline-flex items-center text-primary hover:text-primary/80 transition-colors mb-8">
          ← Back to VDP
        </Link>

        <div className="space-y-12">
          {/* Header */}
          <header className="text-center space-y-4">
            <div className="flex justify-center">
              <Trophy className="w-16 h-16 text-primary" />
            </div>
            <h1 className="text-4xl md:text-5xl font-bold">
              🏆 Security Hall of Fame
            </h1>
            <p className="text-xl text-muted-foreground italic">
              Recognizing researchers who help make critical infrastructure safer
            </p>
          </header>

          {/* Intro */}
          <section className="bg-card border border-border rounded-lg p-8 space-y-4">
            <p className="text-lg leading-relaxed">
              This page recognizes security researchers who have responsibly disclosed vulnerabilities 
              and helped strengthen NouchiX's security posture. We're grateful for their contributions 
              to protecting critical infrastructure.
            </p>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Shield className="w-4 h-4" />
              <span>All researchers listed have followed our responsible disclosure process</span>
            </div>
          </section>

          {/* Hall of Fame List */}
          <section className="space-y-6">
            {researchers.length === 0 ? (
              <div className="bg-card border border-dashed border-border rounded-lg p-12 text-center space-y-4">
                <Star className="w-12 h-12 text-muted-foreground mx-auto" />
                <h2 className="text-2xl font-bold">Be the First!</h2>
                <p className="text-muted-foreground max-w-md mx-auto">
                  No researchers have been recognized yet. Be the first to contribute to our security 
                  through responsible disclosure and earn your place in our Hall of Fame.
                </p>
                <Link 
                  to="/vdp" 
                  className="inline-block bg-primary text-primary-foreground px-6 py-3 rounded-lg font-semibold hover:bg-primary/90 transition-colors mt-4"
                >
                  Learn About Our VDP →
                </Link>
              </div>
            ) : (
              <div className="grid gap-6">
                {researchers.map((researcher, index) => (
                  <div 
                    key={index}
                    className="bg-card border border-border rounded-lg p-6 space-y-3 hover:border-primary/50 transition-colors"
                  >
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <h3 className="text-xl font-bold flex items-center gap-2">
                          {researcher.anonymous ? (
                            <span>Anonymous Researcher</span>
                          ) : (
                            <>
                              <span>{researcher.name}</span>
                              {researcher.handle && (
                                <span className="text-sm text-muted-foreground font-normal">
                                  {researcher.handle}
                                </span>
                              )}
                            </>
                          )}
                        </h3>
                        <p className="text-sm text-muted-foreground">{researcher.date}</p>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-semibold ${
                        researcher.severity === 'Critical' ? 'bg-red-500/20 text-red-600 dark:text-red-400' :
                        researcher.severity === 'High' ? 'bg-orange-500/20 text-orange-600 dark:text-orange-400' :
                        researcher.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-600 dark:text-yellow-400' :
                        'bg-blue-500/20 text-blue-600 dark:text-blue-400'
                      }`}>
                        {researcher.severity}
                      </span>
                    </div>
                    <p className="text-muted-foreground">{researcher.description}</p>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* CTA */}
          <section className="bg-gradient-to-r from-primary/10 to-secondary/10 border border-border rounded-lg p-8 text-center space-y-4">
            <h2 className="text-2xl font-bold">Want to Join the Hall of Fame?</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              If you discover a security vulnerability in our systems, please report it through our 
              Vulnerability Disclosure Program. We'll work with you to address the issue and recognize 
              your contribution (unless you prefer to remain anonymous).
            </p>
            <Link 
              to="/vdp" 
              className="inline-block bg-primary text-primary-foreground px-6 py-3 rounded-lg font-semibold hover:bg-primary/90 transition-colors"
            >
              View Vulnerability Disclosure Program →
            </Link>
          </section>

          {/* Building in Public */}
          <section className="text-center space-y-4">
            <p className="text-sm text-muted-foreground italic">
              🚀 Part of our <Link to="/blog" className="text-primary hover:underline">Building In Public</Link> journey
            </p>
            <p className="text-xs text-muted-foreground">
              Questions about our VDP? Email security@secredknowledgeinc.tech
            </p>
          </section>
        </div>
      </div>
    </div>
  );
};

export default HallOfFame;
