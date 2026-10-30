import { useState, useRef, useEffect } from 'react';
import type { KeyboardEvent } from 'react';
import { Bot, Send, ShieldCheck, Trash2 } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { toast } from 'sonner';
import type { ChatMessage } from '@/types';
import { api } from '@/lib/api';
import { AssistantAnswer } from '@/components/AssistantAnswer';

const MAX_MESSAGE_LENGTH = 2000;

const WELCOME_MESSAGE: ChatMessage = {
  role: 'assistant',
  content:
    "Hello! I'm your AI Security Assistant. I can explain detected threats, answer cybersecurity questions and suggest next steps. I can't take actions on your system, so you stay in control of any response.",
  timestamp: new Date().toISOString(),
};

const SUGGESTIONS = [
  'What threats have been detected recently?',
  'How do I improve my security?',
  'What is ransomware?',
  'What should I do about high severity threats?',
];

export default function AssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([WELCOME_MESSAGE]);
  const [input, setInput] = useState('');
  const [isSending, setIsSending] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isSending]);

  useEffect(() => {
    api.assistant.history().then((history) => {
      if (Array.isArray(history) && history.length > 0) {
        setMessages([
          WELCOME_MESSAGE,
          ...[...history].reverse().flatMap((entry) => [
            { role: 'user' as const, content: entry.query, timestamp: entry.created_at },
            { role: 'assistant' as const, content: entry.response, timestamp: entry.created_at },
          ]),
        ]);
      }
    }).catch(() => {
      // History is supplementary; the assistant remains usable if it is unavailable.
    });
  }, []);

  async function handleClear() {
    if (!window.confirm('Delete your entire chat history? This cannot be undone.')) return;
    try {
      await api.assistant.clearHistory();
      setMessages([WELCOME_MESSAGE]);
      toast.success('Chat history deleted');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not delete chat history');
    }
  }

  async function handleSend(text: string) {
    const trimmed = text.trim();
    if (!trimmed || isSending) return;
    if (trimmed.length > MAX_MESSAGE_LENGTH) {
      toast.error(`Messages must be ${MAX_MESSAGE_LENGTH} characters or fewer`);
      return;
    }

    const userMessage: ChatMessage = { role: 'user', content: trimmed, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsSending(true);

    try {
      const result = await api.assistant.chat(trimmed);
      if (!result || typeof result.response !== 'string') {
        throw new Error('Assistant returned an invalid response');
      }
      setMessages((prev) => [...prev, {
        role: 'assistant',
        content: result.response,
        timestamp: result.timestamp || new Date().toISOString(),
        warning: result.warning,
        sources: result.sources,
        evidence: result.evidence,
        recommendations: result.recommendations,
        uncertain: result.uncertain,
        mode: result.mode,
      }]);
    } catch (error) {
      toast.error('Assistant error', { description: (error as Error).message });
    } finally {
      setIsSending(false);
    }
  }

  function handleKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend(input);
    }
  }

  return (
    <div className="flex h-screen flex-col">
      <TopBar title="AI Security Assistant" description="Get instant answers about threats and security recommendations" />

      <div className="flex flex-1 flex-col gap-4 overflow-hidden p-8">
        <Card className="flex min-h-0 flex-1 flex-col overflow-hidden">
          <div className="flex items-center justify-between border-b p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary/15">
                <ShieldCheck className="h-5 w-5 text-primary" />
              </div>
              <div>
                <div className="font-semibold">SecureAI</div>
                <div className="text-xs text-green-500">Online</div>
              </div>
            </div>
            <Button variant="ghost" size="icon" onClick={handleClear} title="Delete chat history">
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>

          {/* min-h-0 lets this flex child shrink below its content so it scrolls. */}
          <div className="min-h-0 flex-1 overflow-y-auto p-4">
            <div className="space-y-4">
              {messages.map((message, i) => (
                // Index keys are fine: messages are only appended or cleared.
                <div key={i} className={`flex gap-3 ${message.role === 'user' ? 'flex-row-reverse' : ''}`}>
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                    {message.role === 'assistant' ? <Bot className="h-4 w-4" /> : null}
                  </div>
                  <div
                    className={`max-w-[75%] rounded-lg px-4 py-2 text-sm ${
                      message.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted'
                    }`}
                  >
                    {message.role === 'assistant' ? (
                      <AssistantAnswer
                        content={message.content}
                        mode={message.mode}
                        recommendations={message.recommendations}
                        evidence={message.evidence}
                        warning={message.warning}
                        uncertain={message.uncertain}
                      />
                    ) : (
                      <div className="whitespace-pre-wrap">{message.content}</div>
                    )}
                    <div className="mt-1 text-[10px] opacity-60">
                      {new Date(message.timestamp).toLocaleString()}
                    </div>
                  </div>
                </div>
              ))}
              {isSending && (
                <div className="flex gap-3">
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                    <Bot className="h-4 w-4" />
                  </div>
                  <div className="rounded-lg bg-muted px-4 py-2 text-sm opacity-70">Checking SecureX evidence...</div>
                </div>
              )}
              <div ref={scrollRef} />
            </div>
          </div>

          <div className="flex flex-wrap gap-2 border-t p-3">
            {SUGGESTIONS.map((s) => (
              <Button key={s} variant="outline" size="sm" onClick={() => handleSend(s)} disabled={isSending}>
                {s}
              </Button>
            ))}
          </div>

          <div className="flex items-end gap-2 border-t p-4">
            <textarea
              className="flex-1 resize-none rounded-md border bg-background px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
              rows={1}
              placeholder="Ask me anything about cybersecurity..."
              value={input}
              maxLength={MAX_MESSAGE_LENGTH}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
            />
            {input.length > MAX_MESSAGE_LENGTH * 0.8 && (
              <span className="self-center text-xs text-muted-foreground">
                {input.length}/{MAX_MESSAGE_LENGTH}
              </span>
            )}
            <Button onClick={() => handleSend(input)} disabled={isSending || !input.trim()}>
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
