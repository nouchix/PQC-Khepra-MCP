import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { MessageSquare, Sparkles, HelpCircle } from "lucide-react";
import { useState } from "react";

interface PapyrusWizardProps {
    open: boolean;
    onClose: () => void;
    currentView: string;
}

const PapyrusWizard = ({ open, onClose, currentView }: PapyrusWizardProps) => {
    const [messages, setMessages] = useState<Array<{ role: string; content: string }>>([
        {
            role: "papyrus",
            content: "Welcome to the Trust Constellation. I am Papyrus, your guide through the cyber realm. How may I assist you today?",
        },
    ]);
    const [input, setInput] = useState("");

    const contextualHelp = {
        executive: "You're viewing the Executive Dashboard. This shows your organization's risk exposure, compliance score, and top threats prioritized by business impact.",
        compliance: "You're in the Compliance Scorecard. Here you can track CMMC Level 2 progress, view domain-specific controls, and manage your System Security Plan.",
        secops: "This is the SecOps War Room. The Trust Constellation (DAG) shows causal relationships between findings. You can execute remediation playbooks and track incidents.",
        intelligence: "Welcome to the Intelligence Watchtower. Monitor external threats via CISA KEV feed, view your attack surface through Shodan, and track quantum-safety status.",
    };

    const handleSend = () => {
        if (!input.trim()) return;

        setMessages([
            ...messages,
            { role: "user", content: input },
            {
                role: "papyrus",
                content: `I understand you're asking about "${input}". ${contextualHelp[currentView as keyof typeof contextualHelp] || "Let me help you with that."}`,
            },
        ]);
        setInput("");
    };

    return (
        <Dialog open={open} onOpenChange={onClose}>
            <DialogContent className="max-w-2xl bg-slate-900 border-slate-700">
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2 text-slate-200">
                        <Sparkles className="w-5 h-5 text-purple-400" />
                        Papyrus Engine
                    </DialogTitle>
                    <DialogDescription>Your AI-powered guide through the Khepra Protocol</DialogDescription>
                </DialogHeader>

                <div className="space-y-4">
                    {/* Context Banner */}
                    <div className="p-3 rounded-lg bg-purple-950/30 border border-purple-900">
                        <div className="flex items-center gap-2 text-purple-300 text-sm">
                            <HelpCircle className="w-4 h-4" />
                            <span>Currently viewing: <strong>{currentView.toUpperCase()}</strong></span>
                        </div>
                    </div>

                    {/* Chat Messages */}
                    <div className="h-96 overflow-y-auto space-y-4 p-4 rounded-lg bg-slate-950 border border-slate-800">
                        {messages.map((msg, i) => (
                            <div
                                key={i}
                                className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                            >
                                {msg.role === "papyrus" && (
                                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-600 to-pink-600 flex items-center justify-center flex-shrink-0">
                                        <MessageSquare className="w-4 h-4 text-white" />
                                    </div>
                                )}
                                <div
                                    className={`max-w-md p-3 rounded-lg ${msg.role === "user"
                                            ? "bg-blue-600 text-white"
                                            : "bg-slate-800 text-slate-200"
                                        }`}
                                >
                                    {msg.content}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Input */}
                    <div className="flex gap-2">
                        <input
                            type="text"
                            value={input}
                            onChange={(e) => setInput(e.target.value)}
                            onKeyPress={(e) => e.key === "Enter" && handleSend()}
                            placeholder="Ask Papyrus anything..."
                            className="flex-1 px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                        />
                        <button
                            onClick={handleSend}
                            className="px-6 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-medium transition-all"
                        >
                            Send
                        </button>
                    </div>

                    {/* Quick Actions */}
                    <div className="grid grid-cols-2 gap-2">
                        <button
                            onClick={() => setInput("Explain this red node in the DAG")}
                            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm transition-colors"
                        >
                            Explain DAG findings
                        </button>
                        <button
                            onClick={() => setInput("How do I improve my compliance score?")}
                            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm transition-colors"
                        >
                            Improve compliance
                        </button>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    );
};

export default PapyrusWizard;
