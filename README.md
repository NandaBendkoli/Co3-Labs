# Secure Media Vault

One-line: Private media library with signed uploads, row-scoped access, and short-lived download links.

## Quick setup
1. Install Node 18+, pnpm.
2. `pnpm install` at repo root.
3. Create Supabase project. Create private bucket `private`.
4. Run migrations: `supabase db push` or `pnpm db:migrate`.
5. Set env (see .env.example).
6. Start services:
   - API: `pnpm --filter api dev`
   - Web: `pnpm --filter web dev`
7. Create two test users via Supabase Auth for acceptance checks.

## Run tests
`pnpm --filter api test`

## Acceptance checks
(Describe the 8 acceptance checks and how to reproduce locally.)

## Threat model & mitigations
(See THREATS.md section below)
