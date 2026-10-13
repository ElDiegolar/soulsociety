// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

// Set PUBLIC_SITE_URL at build time once the domain is final; sitemap, canonical and OG URLs derive from it.
const site = process.env.PUBLIC_SITE_URL ?? 'https://soulsociety.dev';

export default defineConfig({
  site,
  output: 'static',
  trailingSlash: 'never',
  build: { format: 'file', inlineStylesheets: 'always' },
  compressHTML: true,
  integrations: [sitemap({ changefreq: 'weekly', priority: 0.7, lastmod: new Date() })],
});
