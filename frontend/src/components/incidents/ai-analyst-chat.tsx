"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { askIncidentAi } from "@/lib/api/services/incidents";
import { Bot, Send, User, Clock, ShieldCheck, CornerDownLeft, TerminalSquare } from "lucide-react";
import { toast } from "sonner";

interface Message {
  id: string;
  sender: "user" | "assistant";
  text: string;
  citations?: string[];
  latency_ms?: number;
}

let nextMessageId = 0;
function createMessageId(prefix: string): string {
  nextMessageId += 1;
  return `${prefix}-${nextMessageId}`;
}

const PRESET_PROMPTS = [
  "What evidence triggered this risk score?",
  "Which MITRE techniques are present?",
  "Recommend safest containment simulation",
  "Summarize key packet indicators",
];

export function AiAnalystChat({ incidentId }: { incidentId: string }) {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "initial",
      sender: "assistant",
      text: "Hello, I am your SOC AI Investigator assistant. I am strictly grounded in the cryptographic evidence bundle for this incident. Ask me about detected anomalies, rule matches, packet features, or simulated response actions.",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSend = async (messageText?: string) => {
    const textToSend = (messageText || input).trim();
    if (!textToSend || loading) return;

    const userMsg: Message = {
      id: createMessageId("user"),
      sender: "user",
      text: textToSend,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await askIncidentAi(incidentId, textToSend);
      const aiMsg: Message = {
        id: createMessageId("ai"),
        sender: "assistant",
        text: res.response,
        citations: res.citations,
        latency_ms: res.latency_ms,
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch {
      toast.error("AI analyst query failed. Please verify Ollama is active.");
      const fallbackMsg: Message = {
        id: createMessageId("err"),
        sender: "assistant",
        text: "Could not query Ollama. Local evidence records show deterministic correlation for this incident. Review the constituent detections table above for raw telemetry.",
      };
      setMessages((prev) => [...prev, fallbackMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Card className="border-border">
      <CardHeader className="pb-2.5 border-b border-border bg-muted/10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="rounded border border-border bg-muted/40 p-1 text-muted-foreground">
              <TerminalSquare className="size-3.5" />
            </div>
            <div>
              <CardTitle className="text-sm font-semibold">
                Advisory Evidence Inquiry
              </CardTitle>
              <CardDescription className="text-xs">
                Query local Ollama model grounded strictly in stored incident telemetry.
              </CardDescription>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-0.5 text-[10px] font-mono text-muted-foreground">
              <ShieldCheck className="size-3 text-muted-foreground" />
              Local Ollama
            </span>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-3.5 space-y-3">
        {/* Preset Prompt Suggestions */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-mono text-muted-foreground mr-1">
            Presets:
          </span>
          {PRESET_PROMPTS.map((prompt) => (
            <button
              key={prompt}
              disabled={loading}
              onClick={() => handleSend(prompt)}
              className="rounded border border-border bg-card px-2 py-0.5 text-[11px] text-muted-foreground hover:bg-muted hover:text-foreground transition-colors disabled:opacity-50"
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Message Thread */}
        <div className="space-y-2.5 max-h-72 overflow-y-auto pr-1">
          {messages.map((m) => (
            <div
              key={m.id}
              className={`flex gap-2.5 text-xs ${
                m.sender === "user" ? "justify-end" : "justify-start"
              }`}
            >
              <div
                className={`rounded border px-3 py-2 max-w-[85%] space-y-1 ${
                  m.sender === "user"
                    ? "border-primary/30 bg-primary/10 text-foreground ml-auto"
                    : "border-border bg-muted/20 text-foreground"
                }`}
              >
                <div className="whitespace-pre-wrap leading-relaxed text-xs">{m.text}</div>

                {m.citations && m.citations.length > 0 && (
                  <div className="pt-2 border-t border-border/40 flex flex-wrap items-center gap-1">
                    <span className="text-[10px] text-muted-foreground font-mono">Citations:</span>
                    {m.citations.map((c) => (
                      <span
                        key={c}
                        className="rounded bg-background px-1.5 py-0.5 font-mono text-[9px] text-primary border"
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                )}

                {m.latency_ms !== undefined && (
                  <div className="flex items-center gap-1 text-[9px] text-muted-foreground pt-1">
                    <Clock className="size-2.5" />
                    <span>Inference latency: {m.latency_ms}ms</span>
                  </div>
                )}
              </div>

              {m.sender === "user" && (
                <div className="rounded-full bg-muted text-muted-foreground p-1.5 size-7 shrink-0 flex items-center justify-center">
                  <User className="size-4" />
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex gap-3 text-xs items-center">
              <div className="rounded-full bg-primary/10 text-primary p-1.5 size-7 shrink-0 flex items-center justify-center animate-pulse">
                <Bot className="size-4" />
              </div>
              <div className="rounded-lg bg-muted/60 px-3.5 py-2 border text-muted-foreground font-mono text-xs flex items-center gap-2">
                <span className="size-2 rounded-full bg-primary animate-ping" />
                AI is querying evidence bundle...
              </div>
            </div>
          )}
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex items-center gap-2 pt-2 border-t"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            placeholder="Ask a question about this incident (e.g., 'What was the source port distribution?')..."
            className="flex-1 rounded-md border border-input bg-background px-3 py-2 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring disabled:opacity-50"
          />
          <Button
            type="submit"
            size="sm"
            disabled={loading || !input.trim()}
            className="gap-1 text-xs shrink-0"
          >
            <Send className="size-3.5" />
            Ask
            <CornerDownLeft className="size-3 text-muted-foreground ml-0.5 opacity-60" />
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
