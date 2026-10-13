#!/usr/bin/env node
/**
 * Node entry: wraps the portable Hono app with @hono/node-server and a service-role SupabaseStore.
 * The service-role key never leaves this process; harnesses only ever hold grant tokens.
 */
import { serve } from '@hono/node-server';
import { SupabaseStore } from '@soulsociety/core';
import { createApp } from './app.js';

const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
if (!url || !key) {
  console.error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required');
  process.exit(2);
}
const port = Number(process.env.PORT ?? 8787);
const app = createApp({ store: new SupabaseStore({ url, key }) });

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`soulsociety gateway listening on http://${info.address}:${info.port}`);
});
