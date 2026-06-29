/**
 * env-keys.ts — load provider API keys from environment variables at startup.
 *
 * Set any of these in Render (or your .env) to override / add a provider key
 * without touching the database or re-deploying:
 *
 *   PROVIDER_GOOGLE_KEY=AIza...
 *   PROVIDER_OPENROUTER_KEY=sk-or-...
 *   PROVIDER_GROQ_KEY=gsk_...
 *   PROVIDER_CEREBRAS_KEY=...
 *   PROVIDER_MISTRAL_KEY=...
 *   PROVIDER_NVIDIA_KEY=...
 *   PROVIDER_COHERE_KEY=...
 *   PROVIDER_CLOUDFLARE_KEY=...
 *   PROVIDER_HUGGINGFACE_KEY=...
 *   PROVIDER_ZHIPU_KEY=...
 *   PROVIDER_GITHUB_KEY=...
 *   PROVIDER_OPENCODE_KEY=...
 *
 * If the platform already has a key row in the DB, its encrypted_key is
 * updated in-place (status reset to 'unknown'). If no row exists, one is
 * inserted. This runs once at server boot, before the health checker fires.
 */

import { getDb } from '../db/index.js';
import { encrypt } from '../lib/crypto.js';

const PLATFORM_ENV_MAP: Record<string, string> = {
  google:      'PROVIDER_GOOGLE_KEY',
  openrouter:  'PROVIDER_OPENROUTER_KEY',
  groq:        'PROVIDER_GROQ_KEY',
  cerebras:    'PROVIDER_CEREBRAS_KEY',
  mistral:     'PROVIDER_MISTRAL_KEY',
  nvidia:      'PROVIDER_NVIDIA_KEY',
  cohere:      'PROVIDER_COHERE_KEY',
  cloudflare:  'PROVIDER_CLOUDFLARE_KEY',
  huggingface: 'PROVIDER_HUGGINGFACE_KEY',
  zhipu:       'PROVIDER_ZHIPU_KEY',
  github:      'PROVIDER_GITHUB_KEY',
  opencode:    'PROVIDER_OPENCODE_KEY',
};

export function applyEnvProviderKeys(): void {
  const db = getDb();
  let applied = 0;

  for (const [platform, envVar] of Object.entries(PLATFORM_ENV_MAP)) {
    const rawKey = process.env[envVar]?.trim();
    if (!rawKey) continue;

    const { encrypted, iv, authTag } = encrypt(rawKey);

    const existing = db.prepare(
      'SELECT id FROM api_keys WHERE platform = ? LIMIT 1'
    ).get(platform) as { id: number } | undefined;

    if (existing) {
      db.prepare(
        "UPDATE api_keys SET encrypted_key = ?, iv = ?, auth_tag = ?, status = 'unknown', enabled = 1 WHERE id = ?"
      ).run(encrypted, iv, authTag, existing.id);
      console.log(`[env-keys] Updated key for platform: ${platform}`);
    } else {
      db.prepare(
        "INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, '', ?, ?, ?, 'unknown', 1)"
      ).run(platform, encrypted, iv, authTag);
      console.log(`[env-keys] Added key for platform: ${platform}`);
    }

    applied++;
  }

  if (applied > 0) {
    console.log(`[env-keys] Applied ${applied} provider key(s) from environment variables.`);
  }
}
