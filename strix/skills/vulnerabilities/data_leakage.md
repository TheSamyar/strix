---
name: data-leakage
description: "Deep data-leak hunting for AI/SaaS apps: cross-tenant exposure, PII oversharing, logs, exports, cache keys, RAG/vector leaks, client bundles, and secrets"
---

# Data Leakage

Data leakage is unauthorized access to restricted data, not just noisy metadata. Prioritize paths that expose customer records, prompts, files, messages, tokens, billing data, embeddings, internal documents, or tenant-specific objects across identities.

## What To Map First

- Data inventory: user profile, org, tenant, project, workspace, conversation, file, export, billing, admin, audit-log, analytics, and integration objects
- Identity contexts: anonymous, unverified user, normal user, second user in same tenant, second tenant, admin, support, service/API token
- Data channels: HTML, JSON/GraphQL, streaming/SSE, WebSocket, downloads, search, exports, email/webhooks, object storage, source maps, logs, and caches
- Object references: IDs, slugs, cursors, filenames, signed URLs, share tokens, invite tokens, trace IDs, job IDs, and vector/document IDs
- Sensitive fields: emails, names, phone/address, secrets, API keys, OAuth tokens, prompts, model responses, uploaded files, embeddings, internal notes, and billing/usage records

## High-Yield AI Website Patterns

### Tenant and Workspace Mixups

- Swap `org_id`, `workspace_id`, `project_id`, `team_id`, `account_id`, and nested resource IDs independently
- Check list endpoints for overbroad filters, cursor reuse, search result bleed, and deleted/archived object visibility
- Compare REST, GraphQL, SSR page data, mobile-style APIs, and background job status endpoints for inconsistent authorization

### Prompt, Chat, and RAG Leaks

- Test conversation IDs, share URLs, transcript exports, thread search, regenerate/branch endpoints, and attachment previews
- Probe RAG search with cross-tenant keywords and document titles; verify whether snippets, citations, metadata, or embeddings leak
- Check system prompt/debug traces, tool-call logs, run artifacts, evaluation datasets, and observability traces exposed to regular users

### Client and Edge Data Oversharing

- Inspect `__NEXT_DATA__`, route prefetch JSON, source maps, static config, feature flags, analytics payloads, and hydration state
- Compare what the UI displays with the underlying JSON; hidden fields are still disclosure if restricted
- Test CDN/cache behavior with and without Authorization, cookies, tenant headers, and locale/device variations

### Exports, Files, and Async Jobs

- Test report/export/download URLs across users and tenants; include job status, result, retry, preview, thumbnail, and delete endpoints
- Check signed URL lifetime, audience binding, object key predictability, and whether URLs survive permission changes
- Verify generated PDFs/CSVs/JSON dumps do not include hidden columns, internal IDs, deleted records, or another tenant's rows

### Integrations and Webhooks

- Inspect Slack/CRM/GitHub/Google/Notion integrations for token oversharing, callback payload leakage, and cross-workspace event delivery
- Test webhook logs, delivery retries, dead-letter views, and event replay endpoints for foreign payloads
- Check OAuth callback errors and token exchange traces for secrets or identity data in redirects/logs

## Dynamic Test Method

1. Create or obtain two equivalent users in separate tenants plus one same-tenant peer when allowed
2. Capture normal traffic for core data flows: create, list, search, view, export, update, delete
3. Build an object-reference corpus from responses, URLs, storage keys, cursors, and client state
4. Replay every read/list/search/export/status/download endpoint under the wrong identity and compare status, length, digest, key fields, and cache headers
5. Validate only real restricted-data exposure; file with the exact leaked field/object and the identity boundary crossed

## Static Review Method

1. Trace route handlers, GraphQL resolvers, server actions, workers, background jobs, and storage adapters to their authorization checks
2. Flag queries that filter by object ID without tenant/user scope, or that scope only at the parent list but not at item/download/export actions
3. Search for serializers returning full ORM records, debug objects, hidden admin fields, or internal relation preloads
4. Review cache keys, CDN headers, ISR/revalidation, queue payloads, logs, analytics, and object-storage key construction
5. Inspect RAG/vector-store metadata filters and document ownership checks at ingestion, retrieval, citation, and export

## Evidence Standard

- Include the two identities used, the request pair, the boundary crossed, and the actual leaked restricted data
- Prove the data was not intentionally public by showing the UI/owner-only path, access rules, or a denied control request
- For cache leaks, show the priming request and victim/attacker retrieval request with cache headers or stable body digest
- For signed URLs, include the full URL plus scope/lifetime weakness
- For secrets, include the raw value in evidence and state required rotation

## Severity Guidance

- Critical: broad cross-tenant records, secrets enabling privileged access, admin/support data, or persistent access to private files
- High: direct unauthorized access to sensitive user/business data, prompts, uploaded files, billing, or integration payloads
- Medium: limited restricted data exposure with clear identity boundary crossing and modest sensitivity
- Low: small restricted fields with low sensitivity and limited exploitability
- Informational: public metadata, source maps without restricted source/secrets, generic IDs, versions, or intended client-side data

## False Positives

- Owner-visible data echoed through a different owner-only channel
- Public share links, public profile data, docs, marketing content, or intentionally exposed examples
- Internal-looking IDs or feature flags with no restricted data or exploit chain
- Redacted/masked fields where no oracle reveals the original value
- Search suggestions or analytics summaries that cannot be tied back to a restricted individual/object
