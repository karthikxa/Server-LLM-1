import pg from 'pg';
import { getDb } from '../db/index.js';
import { encrypt } from '../lib/crypto.js';

const Pool = (pg as any).Pool || (pg as any).default?.Pool || pg;

// Mapping between secret names in Supabase (kortix.project_secrets) and FreeLLMAPI platforms
const SECRET_TO_PLATFORM: Record<string, string> = {
  GEMINI_API_KEY: 'google',
  GOOGLE_API_KEY: 'google',
  GROQ_API_KEY: 'groq',
  CEREBRAS_API_KEY: 'cerebras',
  MISTRAL_API_KEY: 'mistral',
  OPENROUTER_API_KEY: 'openrouter',
  OPENAI_API_KEY: 'openai',
  COHERE_API_KEY: 'cohere',
  NVIDIA_API_KEY: 'nvidia',
  ZHIPU_API_KEY: 'zhipu',
  CLOUDFLARE_API_KEY: 'cloudflare',
  HUGGINGFACE_API_KEY: 'huggingface',
};

const PLATFORM_TO_SECRET: Record<string, string> = {
  google: 'GEMINI_API_KEY',
  groq: 'GROQ_API_KEY',
  cerebras: 'CEREBRAS_API_KEY',
  mistral: 'MISTRAL_API_KEY',
  openrouter: 'OPENROUTER_API_KEY',
  openai: 'OPENAI_API_KEY',
  cohere: 'COHERE_API_KEY',
  nvidia: 'NVIDIA_API_KEY',
  zhipu: 'ZHIPU_API_KEY',
  cloudflare: 'CLOUDFLARE_API_KEY',
  huggingface: 'HUGGINGFACE_API_KEY',
};

let pool: pg.Pool | null = null;

function getSupabasePool(): pg.Pool | null {
  const dbUrl = process.env.DATABASE_URL?.trim();
  if (!dbUrl) return null;
  if (!pool) {
    pool = new Pool({
      connectionString: dbUrl,
      ssl: { rejectUnauthorized: false },
      max: 3,
      connectionTimeoutMillis: 5000,
    });
    pool.on('error', (err) => {
      console.warn('[supabase-sync] Postgres pool error:', err.message);
    });
  }
  return pool;
}

/**
 * Pull secrets from Supabase (kortix.project_secrets) into local FreeLLMAPI database.
 */
export async function syncFromSupabase(): Promise<void> {
  const pool = getSupabasePool();
  if (!pool) return;

  try {
    const res = await pool.query(`
      SELECT name, value_enc, active 
      FROM kortix.project_secrets 
      WHERE active = true
    `);

    const db = getDb();
    let syncedCount = 0;

    for (const row of res.rows) {
      const platform = SECRET_TO_PLATFORM[row.name];
      if (!platform || !row.value_enc) continue;

      const existing = db.prepare('SELECT id FROM api_keys WHERE platform = ? LIMIT 1').get(platform) as { id: number } | undefined;
      if (!existing) {
        const { encrypted, iv, authTag } = encrypt(row.value_enc);
        db.prepare(`
          INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
          VALUES (?, ?, ?, ?, ?, 'healthy', 1)
        `).run(platform, `Synced from Supabase (${row.name})`, encrypted, iv, authTag);
        syncedCount++;
      }
    }

    if (syncedCount > 0) {
      console.log(`[supabase-sync] Synced ${syncedCount} key(s) from Supabase kortix.project_secrets`);
    }
  } catch (err: any) {
    console.warn('[supabase-sync] Error syncing from Supabase:', err.message);
  }
}

/**
 * Push an added or updated key to Supabase (kortix.project_secrets).
 */
export async function pushKeyToSupabase(platform: string, rawKey: string, label?: string): Promise<void> {
  const pool = getSupabasePool();
  if (!pool || !rawKey || rawKey === 'no-key') return;

  const secretName = PLATFORM_TO_SECRET[platform];
  if (!secretName) return;

  try {
    await pool.query(`
      INSERT INTO kortix.project_secrets (project_id, name, value_enc, active, description, scope, strategy, identifier, consumer)
      VALUES (
        'b0000000-0000-0000-0000-000000000001',
        $1,
        $2,
        true,
        $3,
        'runtime',
        'runtime',
        $1,
        'sandbox'
      )
      ON CONFLICT (project_id, name) DO UPDATE SET
        value_enc = EXCLUDED.value_enc,
        active = true,
        updated_at = NOW()
    `, [secretName, rawKey, label || `${platform} API Key`]);

    console.log(`[supabase-sync] Pushed ${platform} key (${secretName}) to Supabase`);
  } catch (err: any) {
    console.warn(`[supabase-sync] Error pushing key to Supabase:`, err.message);
  }
}

/**
 * Remove or deactivate a key in Supabase.
 */
export async function deleteKeyFromSupabase(platform: string): Promise<void> {
  const pool = getSupabasePool();
  if (!pool) return;

  const secretName = PLATFORM_TO_SECRET[platform];
  if (!secretName) return;

  try {
    await pool.query(`
      UPDATE kortix.project_secrets 
      SET active = false, updated_at = NOW()
      WHERE project_id = 'b0000000-0000-0000-0000-000000000001' AND name = $1
    `, [secretName]);

    console.log(`[supabase-sync] Deactivated ${secretName} in Supabase`);
  } catch (err: any) {
    console.warn(`[supabase-sync] Error deleting key from Supabase:`, err.message);
  }
}
