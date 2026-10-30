import { AlertTriangle, FileSearch, Lightbulb } from 'lucide-react';
import type { AssistantEvidence } from '@/types';

interface AssistantAnswerProps {
  content: string;
  mode?: 'llm' | 'local';
  recommendations?: string[];
  evidence?: AssistantEvidence[];
  warning?: string;
  uncertain?: boolean;
}

/**
 * Renders an assistant answer with evidence (what SecureX actually found or
 * retrieved) kept visually separate from generated recommendations.
 */
export function AssistantAnswer({ content, mode, recommendations, evidence, warning, uncertain }: AssistantAnswerProps) {
  return (
    <div className="space-y-3">
      {mode && (
        <div className="text-[10px] font-medium uppercase tracking-wide opacity-60">
          {mode === 'llm' ? 'AI-generated answer' : 'Answer from SecureX knowledge base'}
        </div>
      )}
      <div className="whitespace-pre-wrap">{content}</div>

      {recommendations && recommendations.length > 0 && (
        <div className="rounded-md border border-current/15 p-2">
          <div className="mb-1 flex items-center gap-1 text-xs font-semibold">
            <Lightbulb className="h-3.5 w-3.5" /> Recommendations (suggested, not performed)
          </div>
          <ul className="list-disc space-y-1 pl-5 text-xs">
            {recommendations.map((item) => <li key={item}>{item}</li>)}
          </ul>
        </div>
      )}

      {evidence && evidence.length > 0 && (
        <details className="rounded-md border border-current/15 p-2 text-xs">
          <summary className="flex cursor-pointer items-center gap-1 font-semibold">
            <FileSearch className="h-3.5 w-3.5" /> Evidence ({evidence.length})
          </summary>
          <ul className="mt-2 space-y-2">
            {evidence.map((item, i) => (
              <li key={`${item.source}-${i}`}>
                <div className="font-medium">
                  {item.kind === 'securex_record' ? 'SecureX record' : 'Documentation'}: {item.source}
                </div>
                <div className="whitespace-pre-wrap opacity-80">{item.excerpt}</div>
              </li>
            ))}
          </ul>
        </details>
      )}

      {warning && (
        <div
          className={`flex gap-2 rounded-md p-2 text-xs ${
            uncertain ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300' : 'bg-current/5 opacity-80'
          }`}
        >
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>{warning}</span>
        </div>
      )}
    </div>
  );
}
