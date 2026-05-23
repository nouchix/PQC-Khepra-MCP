import { useRef, useState, useEffect, useCallback } from 'react';
import { Sparkles, X, Send, Bot, User } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { cn } from '@/lib/utils';

// ─── Types ───────────────────────────────────────────────────────────────────

interface Message {
  id: string;
  role: 'user' | 'ai';
  text: string;
  toolsCalled?: string[];
  isError?: boolean;
}

interface MCPAskResponse {
  answer?: string;
  response?: string;
  message?: string;
  tools_called?: string[];
}

// ─── Sub-components ──────────────────────────────────────────────────────────

const ThinkingIndicator = () => (
  <div className="flex gap-1 items-center px-3 py-2.5">
    {[0, 1, 2].map((i) => (
      <span
        key={i}
        className="w-1.5 h-1.5 rounded-full bg-primary animate-bounce"
        style={{ animationDelay: `${i * 0.18}s`, animationDuration: '0.9s' }}
      />
    ))}
  </div>
);

const EmptyState = () => (
  <div className="flex flex-col items-center justify-center gap-3 py-10 text-center">
    <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
      <Sparkles className="w-6 h-6 text-primary/60" />
    </div>
    <div>
      <p className="text-xs font-medium text-foreground/70">Khepra AI is ready</p>
      <p className="text-[11px] text-muted-foreground mt-0.5">
        Ask anything about your security posture
      </p>
    </div>
  </div>
);

interface MessageBubbleProps {
  msg: Message;
}

const MessageBubble = ({ msg }: MessageBubbleProps) => (
  <div
    className={cn(
      'flex gap-2 animate-fade-in',
      msg.role === 'user' ? 'flex-row-reverse' : 'flex-row'
    )}
  >
    {/* Avatar */}
    <div
      className={cn(
        'w-6 h-6 rounded-full flex items-center justify-center shrink-0 mt-0.5',
        msg.role === 'user' ? 'bg-primary/20' : 'bg-accent/20'
      )}
    >
      {msg.role === 'user' ? (
        <User className="w-3 h-3 text-primary" />
      ) : (
        <Bot className="w-3 h-3 text-accent" />
      )}
    </div>

    {/* Bubble + tool chips */}
    <div className="flex flex-col gap-1 max-w-[78%]">
      <div
        className={cn(
          'px-3 py-2 rounded-lg text-xs leading-relaxed whitespace-pre-wrap break-words',
          msg.role === 'user'
            ? 'bg-primary/15 text-foreground rounded-tr-none'
            : msg.isError
              ? 'bg-destructive/15 text-destructive rounded-tl-none border border-destructive/20'
              : 'bg-secondary text-foreground rounded-tl-none'
        )}
      >
        {msg.text}
      </div>

      {/* Tool-call chips */}
      {msg.toolsCalled && msg.toolsCalled.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-0.5">
          {msg.toolsCalled.map((tool) => (
            <Badge
              key={tool}
              variant="outline"
              className="text-[9px] h-4 px-1.5 border-primary/30 text-primary/80 font-mono"
            >
              ⚡ {tool}
            </Badge>
          ))}
        </div>
      )}
    </div>
  </div>
);

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_MESSAGES = 20;

// ─── Main Component ───────────────────────────────────────────────────────────

const NLChatPanel = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const sessionId = useRef<string>(crypto.randomUUID());
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Scroll to latest message
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  // Focus input when panel opens
  useEffect(() => {
    if (isOpen) {
      const t = setTimeout(() => inputRef.current?.focus(), 80);
      return () => clearTimeout(t);
    }
  }, [isOpen]);

  const sendMessage = useCallback(async () => {
    const text = input.trim();
    if (!text || isLoading) return;

    const userMsg: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      text,
    };

    setMessages((prev) => [...prev, userMsg].slice(-MAX_MESSAGES));
    setInput('');
    setIsLoading(true);

    try {
      const pqcToken = localStorage.getItem('khepra_pqc_token');
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (pqcToken) headers['X-Khepra-PQC-Token'] = pqcToken;

      const res = await fetch('/api/v1/mcp/ask', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          query: text,
          session_id: sessionId.current,
          max_tools: 5,
        }),
      });

      if (!res.ok) {
        throw new Error(`Server responded with ${res.status}: ${res.statusText}`);
      }

      const data: MCPAskResponse = await res.json();

      const aiMsg: Message = {
        id: crypto.randomUUID(),
        role: 'ai',
        text:
          data.answer ??
          data.response ??
          data.message ??
          'No response received.',
        toolsCalled: Array.isArray(data.tools_called)
          ? data.tools_called
          : undefined,
      };

      setMessages((prev) => [...prev, aiMsg].slice(-MAX_MESSAGES));
    } catch (err) {
      const errMsg: Message = {
        id: crypto.randomUUID(),
        role: 'ai',
        text:
          err instanceof Error
            ? err.message
            : 'Network error. Please check your connection and try again.',
        isError: true,
      };
      setMessages((prev) => [...prev, errMsg].slice(-MAX_MESSAGES));
    } finally {
      setIsLoading(false);
    }
  }, [input, isLoading]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <>
      {/* ── Floating trigger button ── */}
      {!isOpen && (
        <button
          onClick={() => setIsOpen(true)}
          aria-label="Open Khepra AI assistant"
          className={cn(
            'fixed bottom-6 right-6 z-50',
            'w-14 h-14 rounded-full',
            'bg-primary text-primary-foreground',
            'flex items-center justify-center',
            'shadow-[var(--shadow-primary)]',
            'hover:shadow-[var(--shadow-accent)]',
            'hover:scale-110',
            'transition-all duration-300',
            'animate-pulse-glow'
          )}
        >
          <Sparkles className="w-6 h-6" />
        </button>
      )}

      {/* ── Chat panel ── */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 z-50 w-80 h-[480px] flex flex-col animate-slide-in">
          <Card className="flex flex-col h-full bg-card border-border/60 shadow-[var(--shadow-accent)] overflow-hidden rounded-xl">

            {/* Header */}
            <CardHeader className="flex flex-row items-center justify-between p-3 border-b border-border shrink-0 bg-card/80 backdrop-blur-sm">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-full bg-gradient-to-br from-primary/30 to-accent/30 flex items-center justify-center">
                  <Sparkles className="w-3.5 h-3.5 text-primary" />
                </div>
                <span className="font-semibold text-sm text-foreground tracking-tight">
                  Khepra AI
                </span>
                <Badge
                  variant="secondary"
                  className="text-[10px] h-4 px-1.5 bg-accent/10 text-accent border border-accent/30 font-mono"
                >
                  AdinKhepra v2
                </Badge>
              </div>
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7 text-muted-foreground hover:text-foreground hover:bg-secondary"
                onClick={() => setIsOpen(false)}
                aria-label="Close Khepra AI"
              >
                <X className="w-3.5 h-3.5" />
              </Button>
            </CardHeader>

            {/* Messages */}
            <CardContent className="flex-1 p-0 overflow-hidden">
              <ScrollArea className="h-full">
                <div className="flex flex-col gap-3 p-3">
                  {messages.length === 0 && <EmptyState />}

                  {messages.map((msg) => (
                    <MessageBubble key={msg.id} msg={msg} />
                  ))}

                  {isLoading && (
                    <div className="flex gap-2 animate-fade-in">
                      <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0 mt-0.5 bg-accent/20">
                        <Bot className="w-3 h-3 text-accent" />
                      </div>
                      <div className="bg-secondary rounded-lg rounded-tl-none">
                        <ThinkingIndicator />
                      </div>
                    </div>
                  )}

                  {/* Scroll anchor */}
                  <div ref={bottomRef} />
                </div>
              </ScrollArea>
            </CardContent>

            {/* Input row */}
            <div className="flex items-center gap-2 p-3 border-t border-border shrink-0 bg-card/80">
              <Input
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask Khepra AI…"
                className="flex-1 text-xs h-8 bg-input border-border focus-visible:ring-primary/50"
                disabled={isLoading}
                aria-label="Message input"
              />
              <Button
                size="icon"
                className="h-8 w-8 shrink-0"
                onClick={sendMessage}
                disabled={isLoading || !input.trim()}
                aria-label="Send message"
              >
                <Send className="w-3.5 h-3.5" />
              </Button>
            </div>
          </Card>
        </div>
      )}
    </>
  );
};

export default NLChatPanel;
