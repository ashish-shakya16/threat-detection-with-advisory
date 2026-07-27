import { useState, useRef, useEffect } from 'react';
import type { KeyboardEvent } from 'react';
import { Bot, Send, ShieldCheck, Trash2 } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from 'sonner';
import type { ChatMessage } from '@/types';

const WELCOME_MESSAGE: ChatMessage = {
  role: 'assistant',
  content:
    "Hello! I'm your AI Security Assistant. I can help you understand detected threats, get security recommendations, and answer cybersecurity questions. How can I assist you today?",
  timestamp: new Date().toISOString(),
};

const SUGGESTIONS = [
  'What threats have been detected?',
  'How do I improve my security?',
  'What is ransomware?',
  'What should I do about high severity threats?',
];

async function sendChatMessage(message: string): Promise<string> {
  const response = await fetch('/api/assistant/chat', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message }),
  });
  const json = await response.json();
  if (!json.success) {
    throw new Error(json.error || 'Failed to get a response');
  }
  return json.response as string;
}

export default function AssistantPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([WELCOME_MESSAGE]);
  const [input, setInput] = useState('');
  const [isSending, setIsSending] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  async function handleSend(text: string) {
    const trimmed = text.trim();
    if (!trimmed || isSending) return;

    const userMessage: ChatMessage = { role: 'user', content: trimmed, timestamp: new Date().toISOString() };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsSending(true);

    try {
      const response = await sendChatMessage(trimmed);
      setMessages((prev) => [...prev, { role: 'assistant', content: response, timestamp: new Date().toISOString() }]);
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
        <Card className="flex flex-1 flex-col overflow-hidden">
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
            <Button variant="ghost" size="icon" onClick={() => setMessages([WELCOME_MESSAGE])} title="Clear chat">
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>

          <ScrollArea className="flex-1 p-4">
            <div className="space-y-4">
              {messages.map((message, i) => (
                <div key={i} className={`flex gap-3 ${message.role === 'user' ? 'flex-row-reverse' : ''}`}>
                  <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-muted">
                    {message.role === 'assistant' ? <Bot className="h-4 w-4" /> : null}
                  </div>
                  <div
                    className={`max-w-[75%] rounded-lg px-4 py-2 text-sm ${
                      message.role === 'user' ? 'bg-primary text-primary-foreground' : 'bg-muted'
                    }`}
                  >
                    {message.content}
                  </div>
                </div>
              ))}
              <div ref={scrollRef} />
            </div>
          </ScrollArea>

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
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
            />
            <Button onClick={() => handleSend(input)} disabled={isSending || !input.trim()}>
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </Card>
      </div>
    </div>
  );
}
