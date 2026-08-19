with open("src/components/funnel/TrustAnchors.tsx", "r") as f:
    content = f.read()

new_item = """
    {
      icon: Download,
      title: 'Proven Market Traction',
      description: 'Over 424+ verified downloads of the PQC-Khepra-MCP public kernel container on GitHub Package Registry.',
    },
"""
content = content.replace("const trustIndicators = [", "const trustIndicators = [" + new_item)

with open("src/components/funnel/TrustAnchors.tsx", "w") as f:
    f.write(content)

with open("src/components/funnel/HeroSection.tsx", "r") as f:
    content2 = f.read()

hero_badge = """
              <span className="text-xs px-3 py-1.5 bg-yellow-500/10 text-yellow-300 rounded border border-yellow-500/20">
                $7.3M Post-Money Validation
              </span>
              <span className="text-xs px-3 py-1.5 bg-indigo-500/10 text-indigo-300 rounded border border-indigo-500/20 flex items-center gap-1">
                <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-download"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/></svg>
                424+ GHCR Downloads
              </span>
"""
content2 = content2.replace("""              <span className="text-xs px-3 py-1.5 bg-yellow-500/10 text-yellow-300 rounded border border-yellow-500/20">
                $7.3M Post-Money Validation
              </span>""", hero_badge)

with open("src/components/funnel/HeroSection.tsx", "w") as f:
    f.write(content2)

