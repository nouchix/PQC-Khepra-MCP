import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from '@/lib/router-compat';
import {
    Shield, Activity, Globe, Lock, Brain, HelpCircle,
    Search, Home, LogIn, FileText, BarChart3,
    Command, ArrowRight, Zap, Cloud
} from 'lucide-react';

interface CommandItem {
    id: string;
    label: string;
    description?: string;
    icon: React.ComponentType<{ className?: string }>;
    action: () => void;
    keywords: string[];
    section: string;
}

interface CommandPaletteProps {
    isAuthenticated?: boolean;
}

const CommandPalette = ({ isAuthenticated = false }: CommandPaletteProps) => {
    const [isOpen, setIsOpen] = useState(false);
    const [query, setQuery] = useState('');
    const [selectedIndex, setSelectedIndex] = useState(0);
    const inputRef = useRef<HTMLInputElement>(null);
    const listRef = useRef<HTMLDivElement>(null);
    const navigate = useNavigate();

    const runAndClose = useCallback((action: () => void) => {
        action();
        setIsOpen(false);
        setQuery('');
    }, []);

    const commands: CommandItem[] = [
        // Navigation
        { id: 'home', label: 'Go to Homepage', icon: Home, section: 'Navigation', keywords: ['home', 'landing', 'main'], action: () => runAndClose(() => navigate('/')) },
        { id: 'blog', label: 'Security Blog', icon: FileText, section: 'Navigation', keywords: ['blog', 'articles', 'posts', 'news'], action: () => runAndClose(() => navigate('/blog')) },
        { id: 'dod', label: 'DoD Solutions', icon: Shield, section: 'Navigation', keywords: ['dod', 'defense', 'military', 'government'], action: () => runAndClose(() => navigate('/dod')) },
        { id: 'vdp', label: 'Vulnerability Disclosure', icon: HelpCircle, section: 'Navigation', keywords: ['vdp', 'vulnerability', 'disclosure', 'report', 'bug'], action: () => runAndClose(() => navigate('/vdp')) },
        { id: 'privacy', label: 'Privacy Policy', icon: FileText, section: 'Navigation', keywords: ['privacy', 'data', 'policy'], action: () => runAndClose(() => navigate('/privacy')) },
        { id: 'compliance', label: 'Compliance', icon: BarChart3, section: 'Navigation', keywords: ['compliance', 'cmmc', 'nist', 'fedramp'], action: () => runAndClose(() => navigate('/compliance')) },

        // Auth
        ...(isAuthenticated ? [
            { id: 'dashboard', label: 'STIG Dashboard', icon: Shield, section: 'Dashboard', keywords: ['dashboard', 'stig', 'overview'], action: () => runAndClose(() => navigate('/stig-dashboard')) },
            { id: 'scanning', label: 'Asset Scanning', icon: Activity, section: 'Dashboard', keywords: ['scan', 'asset', 'vulnerability'], action: () => runAndClose(() => navigate('/asset-scanning')) },
            { id: 'reports', label: 'Compliance Reports', icon: Globe, section: 'Dashboard', keywords: ['report', 'compliance', 'export'], action: () => runAndClose(() => navigate('/compliance-reports')) },
            { id: 'evidence', label: 'Evidence Collection', icon: Lock, section: 'Dashboard', keywords: ['evidence', 'upload', 'collect'], action: () => runAndClose(() => navigate('/evidence-collection')) },
            { id: 'billing', label: 'Billing', icon: Brain, section: 'Dashboard', keywords: ['billing', 'payment', 'subscription', 'plan'], action: () => runAndClose(() => navigate('/billing')) },
            { id: 'threat-hunting', label: 'Threat Hunting', icon: Shield, section: 'Dashboard', keywords: ['threat', 'hunt', 'forensics', 'behavior'], action: () => runAndClose(() => navigate('/threat-hunting')) },
            { id: 'compliance-autopilot', label: 'Compliance Autopilot', icon: Zap, section: 'Dashboard', keywords: ['compliance', 'autopilot', 'cmmc', 'stig', 'bridge'], action: () => runAndClose(() => navigate('/compliance-autopilot')) },
            { id: 'polymorphic-connector', label: 'Polymorphic Connector', icon: Cloud, section: 'Infrastructure', keywords: ['connect', 'environment', 'agnostic', 'ingestion', 'aws', 'azure', 'iot'], action: () => runAndClose(() => navigate('/integrations?tab=polymorphic')) },
        ] : [
            { id: 'signin', label: 'Sign In', icon: LogIn, section: 'Account', keywords: ['sign', 'login', 'account', 'auth'], action: () => runAndClose(() => navigate('/auth')) },
            { id: 'getstarted', label: 'Get Started', icon: ArrowRight, section: 'Account', keywords: ['start', 'register', 'signup', 'onboard'], action: () => runAndClose(() => navigate('/auth')) },
        ]),
    ];

    const filteredCommands = query.length === 0
        ? commands
        : commands.filter(cmd =>
            cmd.label.toLowerCase().includes(query.toLowerCase()) ||
            cmd.keywords.some(kw => kw.includes(query.toLowerCase()))
        );

    // Group by section
    const grouped = filteredCommands.reduce<Record<string, CommandItem[]>>((acc, cmd) => {
        if (!acc[cmd.section]) acc[cmd.section] = [];
        acc[cmd.section].push(cmd);
        return acc;
    }, {});

    // Keyboard shortcut: Ctrl+K / Cmd+K
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                setIsOpen(prev => !prev);
            }
            if (e.key === 'Escape') {
                setIsOpen(false);
                setQuery('');
            }
        };
        document.addEventListener('keydown', handleKeyDown);
        return () => document.removeEventListener('keydown', handleKeyDown);
    }, []);

    // Focus input on open
    useEffect(() => {
        if (isOpen) {
            setTimeout(() => inputRef.current?.focus(), 50);
            setSelectedIndex(0);
        }
    }, [isOpen]);

    // Arrow key navigation
    useEffect(() => {
        if (!isOpen) return;

        const handleNav = (e: KeyboardEvent) => {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                setSelectedIndex(prev => Math.min(prev + 1, filteredCommands.length - 1));
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setSelectedIndex(prev => Math.max(prev - 1, 0));
            } else if (e.key === 'Enter' && filteredCommands[selectedIndex]) {
                e.preventDefault();
                filteredCommands[selectedIndex].action();
            }
        };

        document.addEventListener('keydown', handleNav);
        return () => document.removeEventListener('keydown', handleNav);
    }, [isOpen, selectedIndex, filteredCommands]);

    // Reset selection when query changes
    useEffect(() => {
        setSelectedIndex(0);
    }, [query]);

    // Scroll selected item into view
    useEffect(() => {
        if (!listRef.current) return;
        const items = listRef.current.querySelectorAll('[data-command-item]');
        items[selectedIndex]?.scrollIntoView({ block: 'nearest' });
    }, [selectedIndex]);

    if (!isOpen) return null;

    let flatIndex = -1;

    return (
        <>
            {/* Backdrop */}
            <div
                className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100]"
                onClick={() => { setIsOpen(false); setQuery(''); }}
                aria-hidden="true"
            />

            {/* Palette */}
            <div
                className="fixed left-1/2 top-[20%] -translate-x-1/2 w-full max-w-lg z-[101]
                   bg-[hsl(220,13%,10%)] border border-[hsl(194,100%,50%,0.2)]
                   rounded-xl shadow-[0_25px_60px_-15px_hsl(194,100%,50%,0.15)] overflow-hidden"
                role="dialog"
                aria-modal="true"
                aria-label="Command palette"
            >
                {/* Search input */}
                <div className="flex items-center gap-3 px-4 py-3 border-b border-white/5">
                    <Search className="h-5 w-5 text-cyan-400 flex-shrink-0" />
                    <input
                        ref={inputRef}
                        type="text"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Type a command or search..."
                        className="flex-1 bg-transparent text-white text-sm placeholder-gray-500 border-none outline-none"
                        aria-label="Search commands"
                    />
                    <kbd className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 text-[10px]
                         text-gray-500 bg-white/5 border border-white/10 rounded font-mono">
                        ESC
                    </kbd>
                </div>

                {/* Results */}
                <div ref={listRef} className="max-h-[320px] overflow-y-auto py-2">
                    {filteredCommands.length === 0 ? (
                        <div className="px-4 py-8 text-center text-gray-500 text-sm">
                            No results for "{query}"
                        </div>
                    ) : (
                        Object.entries(grouped).map(([section, items]) => (
                            <div key={section}>
                                <div className="px-4 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
                                    {section}
                                </div>
                                {items.map((cmd) => {
                                    flatIndex++;
                                    const Icon = cmd.icon;
                                    const isSelected = flatIndex === selectedIndex;
                                    return (
                                        <button
                                            key={cmd.id}
                                            data-command-item
                                            onClick={cmd.action}
                                            className={`w-full flex items-center gap-3 px-4 py-2.5 text-left text-sm transition-colors
                        ${isSelected
                                                    ? 'bg-cyan-500/10 text-cyan-300'
                                                    : 'text-gray-300 hover:bg-white/5 hover:text-white'
                                                }`}
                                        >
                                            <Icon className="h-4 w-4 flex-shrink-0 opacity-60" />
                                            <span className="flex-1">{cmd.label}</span>
                                            {isSelected && (
                                                <ArrowRight className="h-3 w-3 text-cyan-500 opacity-60" />
                                            )}
                                        </button>
                                    );
                                })}
                            </div>
                        ))
                    )}
                </div>

                {/* Footer */}
                <div className="flex items-center justify-between px-4 py-2 border-t border-white/5 text-[10px] text-gray-600">
                    <div className="flex items-center gap-3">
                        <span className="flex items-center gap-1">
                            <kbd className="px-1 py-0.5 bg-white/5 border border-white/10 rounded font-mono">↑↓</kbd>
                            navigate
                        </span>
                        <span className="flex items-center gap-1">
                            <kbd className="px-1 py-0.5 bg-white/5 border border-white/10 rounded font-mono">↵</kbd>
                            select
                        </span>
                    </div>
                    <span className="flex items-center gap-1">
                        <Command className="h-3 w-3" />K to toggle
                    </span>
                </div>
            </div>
        </>
    );
};

export default CommandPalette;
