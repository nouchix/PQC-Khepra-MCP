import { Helmet } from 'react-helmet';
import { Link } from '@/lib/router-compat';
import { ArrowLeft, Calendar, Clock } from 'lucide-react';

export default function BlogList() {
  const blogPosts = [
    {
      id: 'launching-vdp',
      title: '🛡️ Launching Our Vulnerability Disclosure Program',
      excerpt: 'We\'re launching a public Vulnerability Disclosure Program — NouchiX welcomes responsible researchers to help us build resilient systems for critical infrastructure.',
      date: 'January 26, 2025',
      readTime: '6 min read',
      category: 'Building In Public'
    },
    {
      id: 'episode-4-rising-through-ranks',
      title: 'Fit To Think Episode 4: Rising Through Ranks & Expanding Horizons - A New Era for SecRed Knowledge Inc.',
      excerpt: 'Major milestones: Promoted to Sergeant (E5) and strategic partnership with Kaseya/Datto. A new era for SecRed Knowledge Inc.',
      date: 'May 19, 2025',
      readTime: '18 min read',
      category: 'Building In Public'
    },
    {
      id: 'episode-3-founder-inception-story',
      title: 'Fit To Think Episode 3: Founder Inception Story - The "Sacred" Cybersecurity Company',
      excerpt: 'Journey through the rise of SecRed Knowledge Inc., from military-grade cyber operations to launching a veteran-owned AI-powered cybersecurity firm.',
      date: 'April 21, 2025',
      readTime: '17 min read',
      category: 'Building In Public'
    },
    {
      id: 'episode-2-autonomous-ai-deepfakes-leadership',
      title: 'Fit To Think Episode 2: Autonomous AI, Deepfakes, Empathy Crisis & Leadership',
      excerpt: 'Under the rare glow of the Blood Moon, we explore autonomous AI, deepfakes, the empathy crisis, and authentic leadership in our rapidly changing world.',
      date: 'April 21, 2025',
      readTime: '8 min read',
      category: 'AI & Society'
    },
    {
      id: 'episode-1-blood-moon-philosopher-api',
      title: 'Fit To Think Episode 1: Blood Moon, New Beginnings & The Philosopher API',
      excerpt: 'The launch episode exploring The Philosopher API framework, overcoming imposter syndrome, and thriving in the age of technology and change.',
      date: 'March 14, 2025',
      readTime: '15 min read',
      category: 'Philosophy & Innovation'
    },
    {
      id: 'building-cyber-immunity-cmmc-stig-database',
      title: 'I Recently Used Python and AI to Build The Ultimate CMMC → NIST → STIGs Database (FREE Download!)',
      excerpt: 'How SouHimBou AI is redefining compliance with an AI-powered CMMC to STIG mapping database that eliminates spreadsheet chaos.',
      date: 'January 2025',
      readTime: '12 min read',
      category: 'Building In Public'
    }
  ];

  return (
    <>
      <Helmet>
        <title>Blog - SouHimBou AI | Building Cyber Immunity in Public</title>
        <meta name="description" content="Explore insights on AI, cybersecurity, CMMC compliance, and building in public from SouHimBou AI founder Souhimbou Kone." />
        <meta name="keywords" content="AI, cybersecurity, CMMC, NIST, STIGs, compliance automation, building in public, SouHimBou AI" />
        <link rel="canonical" href="https://souhimbou.ai/blog" />
      </Helmet>

      <div className="min-h-screen bg-gradient-to-b from-background to-muted/20">
        <div className="container mx-auto px-4 py-16">
          <Link to="/" className="inline-flex items-center gap-2 text-muted-foreground hover:text-foreground mb-8 transition-colors">
            <ArrowLeft className="w-4 h-4" />
            Back to Home
          </Link>

          <div className="max-w-4xl mx-auto">
            <h1 className="text-4xl md:text-5xl font-bold mb-4">Building Cyber Immunity in Public</h1>
            <p className="text-xl text-muted-foreground mb-12">
              A founder's journal from the field – sharing insights, lessons, and breakthroughs in real-time.
            </p>

            <div className="space-y-8">
              {blogPosts.map((post) => (
                <Link
                  key={post.id}
                  to={`/blog/${post.id}`}
                  className="block group"
                >
                  <article className="bg-card border border-border rounded-lg p-6 hover:shadow-lg transition-all duration-300 hover:border-primary/50">
                    <div className="flex flex-wrap gap-2 mb-3">
                      <span className="inline-block px-3 py-1 text-xs font-semibold bg-primary/10 text-primary rounded-full">
                        {post.category}
                      </span>
                    </div>
                    <h2 className="text-2xl font-bold mb-3 group-hover:text-primary transition-colors">
                      {post.title}
                    </h2>
                    <p className="text-muted-foreground mb-4">
                      {post.excerpt}
                    </p>
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Calendar className="w-4 h-4" />
                        {post.date}
                      </span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        {post.readTime}
                      </span>
                    </div>
                  </article>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
