// backend/lib/llm.js
// Backs base44.integrations.Core.InvokeLLM(). Real, working structured-output
// calls via Anthropic's Messages API when ANTHROPIC_API_KEY is set on the
// backend; otherwise returns a clear "not configured" error the frontend can
// surface instead of silently failing.
const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages';
const MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6';

export async function invokeLLM({ prompt, response_json_schema, file_urls }) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    const err = new Error(
      'AI features are not configured. Set ANTHROPIC_API_KEY in backend/.env to enable InvokeLLM.'
    );
    err.status = 501;
    throw err;
  }

  const content = [{ type: 'text', text: prompt }];
  if (Array.isArray(file_urls)) {
    for (const url of file_urls) {
      content.push({ type: 'text', text: `[Attached file: ${url}]` });
    }
  }

  const body = {
    model: MODEL,
    max_tokens: 1500,
    messages: [{ role: 'user', content }],
  };

  if (response_json_schema) {
    body.tools = [
      {
        name: 'structured_response',
        description: 'Return the response in the required structured format.',
        input_schema: response_json_schema,
      },
    ];
    body.tool_choice = { type: 'tool', name: 'structured_response' };
  }

  const res = await fetch(ANTHROPIC_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`Anthropic API error (${res.status}): ${text.slice(0, 300)}`);
    err.status = 502;
    throw err;
  }

  const data = await res.json();

  if (response_json_schema) {
    const toolUse = data.content?.find((c) => c.type === 'tool_use');
    if (toolUse) return toolUse.input;
    return {};
  }

  const textBlock = data.content?.find((c) => c.type === 'text');
  return { reply: textBlock?.text || '' };
}
