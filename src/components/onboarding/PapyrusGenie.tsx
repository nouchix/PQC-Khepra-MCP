import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Brain, X, Shield, Zap, ChevronRight, User } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { AdinkraSymbolDisplay } from '@/components/khepra/AdinkraSymbolDisplay';

interface PapyrusGenieProps {
    delay?: number;
}

export const PapyrusGenie = ({ delay = 2500 }: PapyrusGenieProps) => {
    const [isVisible, setIsVisible] = useState(false);
    const [isExpanded, setIsExpanded] = useState(false);
    const [showBubble, setShowBubble] = useState(false);

    useEffect(() => {
        const timer = setTimeout(() => {
            setIsVisible(true);
            setTimeout(() => setShowBubble(true), 500);
        }, delay);

        return () => clearTimeout(timer);
    }, [delay]);


    return (
        <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end gap-4 pointer-events-none">
            <AnimatePresence>
                {isVisible && (
                    <>
                        {/* Contextual Bubble */}
                        {showBubble && !isExpanded && (
                            <motion.div
                                initial={{ opacity: 0, scale: 0.8, y: 10 }}
                                animate={{ opacity: 1, scale: 1, y: 0 }}
                                exit={{ opacity: 0, scale: 0.8, y: 10 }}
                                className="pointer-events-auto"
                            >
                                <Card className="bg-slate-900/90 border-primary/30 backdrop-blur-xl shadow-2xl shadow-primary/20 max-w-[280px]">
                                    <CardContent className="p-4">
                                        <p className="text-sm text-slate-200 leading-relaxed">
                                            "I see you've arrived! I am <span className="text-primary font-bold">Papyrus</span>. Should we begin the heavy lifting of your STIG setup together?"
                                        </p>
                                        <div className="flex gap-2 mt-3">
                                            <Button
                                                size="sm"
                                                variant="cyber"
                                                className="h-8 text-xs flex-1"
                                                onClick={() => setIsExpanded(true)}
                                            >
                                                Let's Begin
                                            </Button>
                                            <Button
                                                size="sm"
                                                variant="ghost"
                                                className="h-8 text-xs px-2"
                                                onClick={() => setShowBubble(false)}
                                            >
                                                <X className="h-3 w-3" />
                                            </Button>
                                        </div>
                                    </CardContent>
                                </Card>
                            </motion.div>
                        )}

                        {/* Expanded Interface */}
                        {isExpanded && (
                            <motion.div
                                initial={{ opacity: 0, scale: 0.95, y: 20 }}
                                animate={{ opacity: 1, scale: 1, y: 0 }}
                                exit={{ opacity: 0, scale: 0.95, y: 20 }}
                                className="pointer-events-auto w-[350px]"
                            >
                                <Card className="bg-slate-950/95 border-primary/40 backdrop-blur-2xl shadow-2xl shadow-primary/30 overflow-hidden">
                                    <div className="bg-gradient-to-r from-primary/20 to-purple-500/20 px-4 py-3 border-b border-primary/20 flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                            <Brain className="h-4 w-4 text-primary" />
                                            <span className="font-semibold text-sm">Papyrus Assistant</span>
                                        </div>
                                        <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => setIsExpanded(false)}>
                                            <X className="h-4 w-4" />
                                        </Button>
                                    </div>
                                    <CardContent className="p-0">
                                        <div className="h-[400px] flex flex-col">
                                            <div className="flex-1 p-4 space-y-4 overflow-y-auto">
                                                <div className="flex gap-3">
                                                    <div className="w-8 h-8 rounded-full bg-primary/20 flex-shrink-0 flex items-center justify-center">
                                                        <AdinkraSymbolDisplay symbolName="Sankofa" size="small" showMatrix={false} className="w-4 h-4" />
                                                    </div>
                                                    <div className="bg-slate-800/50 rounded-lg rounded-tl-none p-3 border border-slate-700/50">
                                                        <p className="text-sm">
                                                            Welcome to your sovereign workspace. I've detected that you have some unconfigured assets.
                                                            Shall we start the <span className="text-primary">Deep Scan</span> process?
                                                        </p>
                                                    </div>
                                                </div>

                                                <div className="space-y-2 pl-11">
                                                    <Button variant="outline" size="sm" className="w-full justify-start gap-2 bg-slate-900/50 border-primary/20 hover:border-primary/50">
                                                        <Zap className="h-3 w-3 text-yellow-500" />
                                                        <span>Setup Cloud Infrastructure</span>
                                                        <ChevronRight className="h-3 w-3 ml-auto text-slate-500" />
                                                    </Button>
                                                    <Button variant="outline" size="sm" className="w-full justify-start gap-2 bg-slate-900/50 border-primary/20 hover:border-primary/50">
                                                        <Shield className="h-3 w-3 text-primary" />
                                                        <span>Configure STIG Baselines</span>
                                                        <ChevronRight className="h-3 w-3 ml-auto text-slate-500" />
                                                    </Button>
                                                    <Button variant="outline" size="sm" className="w-full justify-start gap-2 bg-slate-900/50 border-primary/20 hover:border-primary/50">
                                                        <User className="h-3 w-3 text-blue-500" />
                                                        <span>Personalize My Experience</span>
                                                        <ChevronRight className="h-3 w-3 ml-auto text-slate-500" />
                                                    </Button>
                                                </div>
                                            </div>

                                            <div className="p-3 border-t border-slate-800 bg-slate-900/50 flex gap-2">
                                                <div className="flex-1 h-9 rounded-md bg-slate-800/50 border border-slate-700 flex items-center px-3 text-xs text-slate-400">
                                                    Type a command or ask a question...
                                                </div>
                                                <Button size="icon" className="h-9 w-9 bg-primary">
                                                    <ChevronRight className="h-4 w-4" />
                                                </Button>
                                            </div>
                                        </div>
                                    </CardContent>
                                </Card>
                            </motion.div>
                        )}

                        {/* Avatar Toggle */}
                        <motion.div
                            layoutId="genie-avatar"
                            className="pointer-events-auto"
                            onClick={() => {
                                if (isExpanded) {
                                    setIsExpanded(false);
                                } else {
                                    setIsExpanded(true);
                                    setShowBubble(false);
                                }
                            }}
                        >
                            <Button
                                size="icon"
                                className={`h-14 w-14 rounded-full shadow-2xl relative group transition-all duration-500 ${isExpanded ? 'bg-slate-950 border-primary/50' : 'bg-primary shadow-primary/40'
                                    }`}
                            >
                                <Brain className={`h-7 w-7 transition-all duration-500 ${isExpanded ? 'text-primary scale-110' : 'text-white'}`} />
                                <div className="absolute -inset-1 rounded-full bg-primary/20 animate-ping pointer-events-none" />
                                <div className="absolute inset-0 rounded-full border-2 border-primary/50 scale-110 opacity-0 group-hover:opacity-100 transition-opacity" />
                                {!isExpanded && (
                                    <Badge className="absolute -top-1 -right-1 h-5 w-5 p-0 flex items-center justify-center bg-red-500 border-2 border-slate-950">
                                        1
                                    </Badge>
                                )}
                            </Button>
                        </motion.div>
                    </>
                )}
            </AnimatePresence>
        </div>
    );
};

export default PapyrusGenie;
