# Plan 5: React Frontend Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Depends on Plans 1-4** being complete — this plan assumes `DatabaseManager` is leak-free, Flask auth (`login_required`, `/login`, session cookies) is in place, all `/api/*` routes return real data (no stubs), and severity/`detected_at` bugs are fixed. If any `/api/*` route still returns a hardcoded stub, this plan's frontend will faithfully render that stub — it does not re-fix backend bugs.

**Goal:** Replace the server-rendered Flask/Jinja2/vanilla-JS dashboard (6 pages, `src/dashboard/templates/` + `src/dashboard/static/`) with a React + TypeScript + Vite single-page application styled with Tailwind CSS and shadcn/ui components, while keeping the existing Flask backend as a pure JSON API and preserving session-cookie authentication.

**Architecture:** New `frontend/` directory at the repo root, fully independent Node/npm project (Vite dev server, its own `package.json`). During development, Vite's dev server proxies `/api/*` and `/socket.io/*` requests to Flask (running on a different port) so the browser sees same-origin requests and the session cookie works without CORS gymnastics. For production, `npm run build` outputs static files that Flask serves from a new catch-all route, replacing the old Jinja2 templates. Flask's existing `/login` and `/logout` routes are converted to JSON API endpoints (`POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`) since a SPA can't use server-side redirects/form posts the way the old Jinja2 login page did. React Router handles all client-side routing; a `ProtectedRoute` wrapper checks auth state (via `/api/auth/me`) before rendering any page and redirects to `/login` otherwise, mirroring what `login_required` did server-side.

**Tech Stack:** React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, React Router v6, TanStack Query (React Query) for data fetching/caching, socket.io-client for real-time updates, Recharts (shadcn/ui's charting recommendation, replaces Chart.js) for charts.

---

## Context You Need

- Existing pages to replace: `dashboard.html` (main stats/charts/recent threats), `threats.html` (filterable threat list + detail modal), `analytics.html` (trend/category/risk charts + summary stats), `assistant.html` (chat UI), `settings.html` (currently static/non-functional form — no `id`s wired to JS, no save handler; this plan makes it functional against real config), `login.html` (from Plan 2).
- Existing API surface (all under `/api/`, all now `@login_required` per Plan 2): `GET /api/stats`, `GET /api/threats?limit=&hours=`, `GET /api/threat/<id>`, `GET /api/system-metrics`, `GET /api/threat-timeline?hours=`, `POST /api/scan/start`, `GET /api/monitoring/status`, `POST /api/monitoring/start`, `POST /api/monitoring/stop`, `POST /api/assistant/chat`, plus blueprints: `GET /api/threats/`, `GET /api/threats/<id>`, `PUT /api/threats/<id>/status`, `GET /api/threats/critical`, `GET /api/stats/`, `GET /api/stats/by-category`, `GET /api/stats/by-severity`, `GET /api/analytics/timeline?days=`, `GET /api/analytics/top-threats?limit=`, `GET /api/analytics/detection-rate?period=`, `GET/POST /api/notifications/*`, `GET/POST /api/ml/*`.
- Response shape convention (used by every route): `{"success": true, "data": ...}` or `{"success": false, "error": "..."}`. Some legacy routes use `"count"` alongside `"data"` (e.g. `/api/threats/`). Threat objects have fields: `id, threat_name, category, risk_level, risk_score, severity, confidence, source, description, detected_at, status` (matches `schema.sql`'s `threats` table — NOT `timestamp`, which was the pre-rewrite bug in `main.js:240`).
- Socket.IO events (server → client): `connected` (on connect), `new_threats` (`{count, threats, timestamp}`), `system_metrics` (`{cpu, memory, timestamp}`), `stats_update` (emitted on `request_update`).
- Auth: session cookie set by Flask (`flask.session['username']`), `login_required` decorator returns `401 {"success": false, "error": "Authentication required"}` JSON for any `/api/*` path when unauthenticated (see `src/auth.py`). No token/JWT exists — this plan keeps cookie-based auth, so all `fetch`/axios calls must include `credentials: 'include'`.
- The current `/login` route (`src/dashboard/app.py`) renders `login.html` and handles form POST with a redirect — this plan converts it to a JSON endpoint since the SPA will build its own login form.
- No API endpoint currently exists for reading/writing settings (the `settings.html` page is static markup with unwired inputs) — this plan does NOT invent new backend settings-persistence endpoints (out of scope, would require new DB schema/config-writing logic); the new Settings page will display real read-only system info (version, DB type, rules loaded count — already available via existing endpoints or new lightweight ones added in Task 3) and will surface the notification recipient management that already has working `/api/notifications/*` endpoints, rather than pretend to save monitoring thresholds that have no backend persistence.

## File Structure

```
frontend/
├── package.json
├── vite.config.ts
├── tsconfig.json
├── tailwind.config.js
├── postcss.config.js
├── index.html
├── components.json          (shadcn/ui config)
├── src/
│   ├── main.tsx
│   ├── App.tsx               (router setup)
│   ├── index.css             (Tailwind directives + CSS variables for theme)
│   ├── lib/
│   │   ├── api.ts            (fetch wrapper, typed API client)
│   │   ├── socket.ts         (socket.io-client singleton)
│   │   └── utils.ts          (shadcn's cn() helper, formatters)
│   ├── types/
│   │   └── index.ts          (Threat, Stats, SystemMetrics, etc. TypeScript interfaces)
│   ├── hooks/
│   │   ├── useAuth.ts        (auth state, login/logout)
│   │   ├── useStats.ts       (React Query hook)
│   │   ├── useThreats.ts
│   │   ├── useSystemMetrics.ts
│   │   └── useSocket.ts      (subscribes to socket events, invalidates queries)
│   ├── components/
│   │   ├── ui/                (shadcn/ui generated components: button, card, badge, etc.)
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx
│   │   │   ├── TopBar.tsx
│   │   │   └── AppLayout.tsx
│   │   ├── ProtectedRoute.tsx
│   │   ├── StatCard.tsx
│   │   ├── SeverityBadge.tsx
│   │   ├── ThreatTable.tsx
│   │   ├── ThreatDetailDialog.tsx
│   │   └── ConnectionStatus.tsx
│   └── pages/
│       ├── LoginPage.tsx
│       ├── DashboardPage.tsx
│       ├── ThreatsPage.tsx
│       ├── AnalyticsPage.tsx
│       ├── AssistantPage.tsx
│       └── SettingsPage.tsx
```

Backend changes (existing repo, not `frontend/`):
- Modify: `src/dashboard/app.py` — convert `/login`, `/logout` to JSON API, add `GET /api/auth/me`, add catch-all static-serving route for the built SPA, remove `render_template` calls for the 6 replaced pages (keep `src/dashboard/templates/` deletion as a final cleanup step, not upfront, so rollback is easy mid-plan).
- Modify: `src/database/db_manager.py` — add `get_system_info()` method (rules count, DB type, version) backing the new read-only Settings page section.
- Delete (final task only): `src/dashboard/templates/dashboard.html`, `threats.html`, `analytics.html`, `assistant.html`, `settings.html`, `login.html`; `src/dashboard/static/` (css/js).

---

### Task 1: Scaffold the Vite + React + TypeScript + Tailwind + shadcn/ui project

**Files:**
- Create: `frontend/` (entire new directory via tooling, not hand-written)

- [ ] **Step 1: Verify Node.js and npm are available**

Run: `node --version && npm --version`
Expected: Node >= 18.x, npm >= 9.x. If not installed, stop and inform the user — Node.js must be installed manually before this plan can proceed (this plan cannot install system-level tooling).

- [ ] **Step 2: Scaffold the Vite React-TS template**

Run (from repo root `e:\PROJECT\cybersecurity-threat-advisor`):
```bash
npm create vite@latest frontend -- --template react-ts
```
Expected: `frontend/` directory created with `package.json`, `src/main.tsx`, `src/App.tsx`, `vite.config.ts`, `tsconfig.json`, `index.html`.

- [ ] **Step 3: Install base dependencies**

Run:
```bash
cd frontend
npm install
```
Expected: `node_modules/` created, no errors.

- [ ] **Step 4: Install Tailwind CSS v4 via its Vite plugin**

Tailwind v4 (the current version as of this plan) uses a Vite plugin instead of PostCSS config files — there is no `tailwind.config.js`, no `postcss.config.js`, and no `tailwindcss init` command in v4. Run (still inside `frontend/`):
```bash
npm install tailwindcss @tailwindcss/vite
```
Expected: both packages added to `package.json` dependencies, no config files created (that's expected — v4 configures via CSS, not JS config files).

- [ ] **Step 5: Add the Tailwind import to the base CSS file**

Replace the entire contents of `frontend/src/index.css` with:

```css
@import "tailwindcss";
```

(The rest of the theme setup — CSS variables, dark mode variant — is added by the shadcn/ui CLI in Step 10, which appends to this file.)

- [ ] **Step 6: Configure path aliases for shadcn/ui (`@/` imports)**

Edit `frontend/tsconfig.json` — find the `compilerOptions` object and add this key (merge with existing options, don't replace the whole file). Note: do NOT add `baseUrl` — TypeScript 6.0+ deprecates `baseUrl` when combined with `paths` (warns it "will stop functioning in TypeScript 7.0"); `paths` alone resolves correctly in bundler module resolution mode without it:

```json
{
  "compilerOptions": {
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

Run: `cat frontend/tsconfig.json` first to see the exact existing structure, then use Edit to insert `"paths"` into the existing `compilerOptions` block without removing any existing keys (Vite's React-TS template typically already has a `references` array pointing to `tsconfig.app.json` and `tsconfig.node.json` — if so, add the `paths` key to `tsconfig.app.json`'s `compilerOptions` instead, since that's the one that actually applies to `src/`; add it to the root `tsconfig.json` too, since the shadcn/ui CLI reads path aliases from the root file and may otherwise miswrite generated component files to a literal `./@/` directory instead of `./src/` — verify with `ls` after the first `shadcn add` command and move files into `src/` if this happens).

Run: `npx tsc --version` — if it reports 6.0 or higher, `baseUrl` must be omitted per the note above.

- [ ] **Step 7: Configure Vite's resolver and the Tailwind v4 plugin**

Edit `frontend/vite.config.ts`, replacing its full contents with:

```ts
import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
      },
      '/socket.io': {
        target: 'http://127.0.0.1:5000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
```

- [ ] **Step 8: Install `@types/node` (needed for `path` import above)**

Run: `npm install -D @types/node`

- [ ] **Step 9: Initialize shadcn/ui (Tailwind v4 aware — CLI detects v4 automatically, no config file prompts)**

Run non-interactively with explicit flags (the current CLI generation names presets like `nova`/`vega`/`maia` and asks for a component-primitive base like `radix`/`base`/`aria` — passing these upfront avoids interactive prompts that block automated execution):

```bash
npx shadcn@latest init -t vite -b radix -p nova -y
```

If this fails partway (e.g. "Could not load the workspace config" right after "Writing components.json") — this can happen on a fresh run — simply re-run the exact same command. `components.json` will already exist on the second run, so also pass `--force --reinstall` to skip the "re-install existing components?" prompt:

```bash
npx shadcn@latest init -t vite -b radix -p nova -y --force --reinstall
```

Do not use a short shell timeout on this command — the "Installing dependencies" and "Updating files" steps can take longer than 15-20 seconds; let it run to completion (it prints "Project initialization completed." when done).

Expected: `frontend/components.json` created (with `"style": "radix-nova"`), `frontend/src/lib/utils.ts` created (the `cn()` helper), `frontend/src/index.css` expanded with `@theme inline { ... }`, `:root { ... }`, and `.dark { ... }` blocks (OKLCH color values, per shadcn/ui's Tailwind v4 support). No `tailwind.config.js` is created — this is expected and correct for v4.

**Known Windows CLI bug to check for:** after this step (and after every `shadcn add` step later in this task), run `ls frontend/src/components/ui/ 2>/dev/null || ls frontend/@` — if a literal `frontend/@` directory exists instead of files appearing under `frontend/src/`, the CLI's alias resolution wrote to the wrong path. Fix by moving the contents into the correct `src/` location (e.g. `mv frontend/@/lib/utils.ts frontend/src/lib/utils.ts`, `mv frontend/@/components/ui/*.tsx frontend/src/components/ui/`) and `rm -rf frontend/@`. Adding `"paths": {"@/*": ["./src/*"]}` to the root `frontend/tsconfig.json`'s `compilerOptions` (not just `tsconfig.app.json`) before running further `shadcn add` commands prevents this from recurring.

- [ ] **Step 10: Enable dark mode by default (matching the existing app's dark theme)**

Edit `frontend/index.html`'s `<html>` tag to include the `dark` class so shadcn's `@custom-variant dark (&:is(.dark *))` applies without a theme toggle:

```html
<html lang="en" class="dark">
```

- [ ] **Step 11: Install the shadcn/ui components this app will need**

Run (can be batched into one command with `-y` to skip confirmation prompts):
```bash
npx shadcn@latest add button card badge table dialog input select tabs sonner skeleton separator switch label scroll-area avatar -y
```
After this completes, check for the Windows alias-resolution bug described in Step 9 (`ls frontend/@` — if it exists, move its contents into `frontend/src/` and delete it).

Expected: `frontend/src/components/ui/` populated with `button.tsx`, `card.tsx`, `badge.tsx`, `table.tsx`, `dialog.tsx`, `input.tsx`, `select.tsx`, `tabs.tsx`, `sonner.tsx`, `skeleton.tsx`, `separator.tsx`, `switch.tsx`, `label.tsx`, `scroll-area.tsx`, `avatar.tsx`. Note: this plan uses `sonner` (shadcn/ui's current recommendation), NOT the deprecated `toast`/`use-toast` component — every later task that shows notifications calls `import { toast } from 'sonner'` directly rather than a `useToast()` hook.

`sonner`'s own dependency is `next-themes`, which the shadcn CLI installs automatically — this is fine even outside Next.js since this plan doesn't build a light/dark toggle (dark mode is hardcoded via the `dark` class from Step 10), so `next-themes`' theme-switching logic simply goes unused.

- [ ] **Step 12: Install remaining runtime dependencies**

Run:
```bash
npm install react-router-dom @tanstack/react-query socket.io-client recharts lucide-react
```

- [ ] **Step 13: Verify the dev server starts cleanly**

Run: `npm run dev` (in background, then check output)
Expected: Vite prints a local URL like `http://localhost:5173/` with no errors. Stop the server after confirming (Ctrl+C or kill the background process) before continuing.

- [ ] **Step 14: Commit**

```bash
cd ..
git add frontend/
git commit -m "feat: scaffold React + TypeScript + Vite + Tailwind + shadcn/ui frontend"
```

Note: `frontend/node_modules/` must be gitignored. Check `.gitignore` at repo root includes `node_modules/` — if not, add it before this commit (run `grep -n node_modules .gitignore` first; Vite's scaffold also creates `frontend/.gitignore` covering this automatically, so this is likely already handled).

---

### Task 2: TypeScript types and API client

**Files:**
- Create: `frontend/src/types/index.ts`
- Create: `frontend/src/lib/api.ts`
- Create: `frontend/src/lib/socket.ts`

- [ ] **Step 1: Define TypeScript interfaces matching the real backend response shapes**

Create `frontend/src/types/index.ts`:

```typescript
export interface Threat {
  id: number;
  threat_name: string;
  category: string;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  risk_score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  source: string;
  description: string;
  detected_at: string;
  status: 'active' | 'resolved' | 'ignored' | 'escalated';
  advisory?: Advisory | null;
}

export interface Advisory {
  id: number;
  threat_id: number;
  title: string;
  description: string;
  reason: string;
  recommended_actions: string;
  reference_links: string;
  generated_at: string;
}

export interface ThreatStatistics {
  total_threats: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  active_critical: number;
  time_window_hours: number;
}

export interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  network_connections: number;
  process_count: number;
  timestamp: string;
}

export interface TimelinePoint {
  time: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DailyTimelinePoint {
  date: string;
  count: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  count?: number;
}

export interface User {
  username: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface NotificationStatus {
  status: 'enabled' | 'disabled';
  recipients: string[];
  notification_rules: {
    critical: boolean;
    high: boolean;
    medium: boolean;
    low: boolean;
  };
}

export interface MLStatus {
  status: string;
  trained: boolean;
  model_path: string;
}

export interface SystemInfo {
  version: string;
  database_type: string;
  rules_loaded: number;
}
```

- [ ] **Step 2: Write the API client with typed fetch wrappers**

Create `frontend/src/lib/api.ts`:

```typescript
import type {
  ApiResponse,
  Threat,
  ThreatStatistics,
  SystemMetrics,
  TimelinePoint,
  DailyTimelinePoint,
  User,
  NotificationStatus,
  MLStatus,
  SystemInfo,
} from '@/types';

const BASE_URL = '';

class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (response.status === 401) {
    throw new ApiError('Authentication required', 401);
  }

  const json: ApiResponse<T> = await response.json();

  if (!json.success) {
    throw new ApiError(json.error || 'Request failed', response.status);
  }

  return json.data as T;
}

export const api = {
  auth: {
    login: (username: string, password: string) =>
      request<User>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }),
    logout: () => request<void>('/api/auth/logout', { method: 'POST' }),
    me: () => request<User>('/api/auth/me'),
  },
  stats: {
    get: () => request<ThreatStatistics>('/api/stats'),
  },
  threats: {
    list: (params: { limit?: number; hours?: number } = {}) => {
      const query = new URLSearchParams();
      if (params.limit) query.set('limit', String(params.limit));
      if (params.hours) query.set('hours', String(params.hours));
      return request<Threat[]>(`/api/threats?${query.toString()}`);
    },
    get: (id: number) => request<Threat>(`/api/threat/${id}`),
    updateStatus: (id: number, status: string) =>
      request<void>(`/api/threats/${id}/status`, {
        method: 'PUT',
        body: JSON.stringify({ status }),
      }),
  },
  systemMetrics: {
    get: () => request<SystemMetrics>('/api/system-metrics'),
  },
  timeline: {
    hourly: (hours: number) => request<TimelinePoint[]>(`/api/threat-timeline?hours=${hours}`),
    daily: (days: number) => request<DailyTimelinePoint[]>(`/api/analytics/timeline?days=${days}`),
  },
  scan: {
    start: () => request<{ threats: unknown[]; message: string }>('/api/scan/start', { method: 'POST' }),
  },
  monitoring: {
    status: () => request<{ active: boolean }>('/api/monitoring/status'),
    start: () => request<void>('/api/monitoring/start', { method: 'POST' }),
    stop: () => request<void>('/api/monitoring/stop', { method: 'POST' }),
  },
  assistant: {
    chat: (message: string) => request<string>('/api/assistant/chat', {
      method: 'POST',
      body: JSON.stringify({ message }),
    }),
  },
  notifications: {
    status: () => request<NotificationStatus>('/api/notifications/status'),
    addRecipient: (email: string) => request<void>('/api/notifications/recipients', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),
    removeRecipient: (email: string) => request<void>(`/api/notifications/recipients/${encodeURIComponent(email)}`, {
      method: 'DELETE',
    }),
    sendTest: () => request<void>('/api/notifications/test', { method: 'POST' }),
  },
  ml: {
    status: () => request<MLStatus>('/api/ml/status'),
    train: () => request<{ samples_used: number }>('/api/ml/train', { method: 'POST' }),
  },
  system: {
    info: () => request<SystemInfo>('/api/system-info'),
  },
};

export { ApiError };
```

Note: `assistant.chat`'s response type is `string` because `/api/assistant/chat` returns `{"success": true, "response": "..."}`, NOT `{"data": "..."}` — this is an inconsistency in the existing Flask route (`src/dashboard/app.py`'s `assistant_chat` uses the key `response`, not `data`, unlike every other endpoint). Handle this special case directly in Task 6's `AssistantPage` implementation rather than forcing the generic `request<T>()` wrapper to support two different envelope shapes — write a small dedicated fetch call for this one endpoint instead of using `api.assistant.chat` through the shared `request()` helper. Remove `assistant: { chat: ... }` from the `api` object above and instead implement it inline in `useAssistantChat` (Task 6).

- [ ] **Step 3: Write the Socket.IO client singleton**

Create `frontend/src/lib/socket.ts`:

```typescript
import { io, Socket } from 'socket.io-client';

export const socket: Socket = io({
  autoConnect: false,
  withCredentials: true,
});
```

- [ ] **Step 4: Remove the `assistant.chat` method from `api.ts` per the Step 2 note**

Edit `frontend/src/lib/api.ts`, remove:
```typescript
  assistant: {
    chat: (message: string) => request<string>('/api/assistant/chat', {
      method: 'POST',
      body: JSON.stringify({ message }),
    }),
  },
```

- [ ] **Step 5: Verify TypeScript compiles with no errors**

Run: `cd frontend && npx tsc --noEmit`
Expected: No errors (or only errors about unused variables in the default Vite template's `App.tsx`/`main.tsx`, which will be replaced in Task 3).

- [ ] **Step 6: Commit**

```bash
cd ..
git add frontend/src/types frontend/src/lib
git commit -m "feat: add TypeScript types and typed API client for frontend"
```

---

### Task 3: Backend changes — JSON auth endpoints, system-info endpoint, static file serving

**Files:**
- Modify: `src/dashboard/app.py`
- Modify: `src/database/db_manager.py`
- Test: `tests/test_auth.py` (append)

- [ ] **Step 1: Write the failing test for the new JSON auth endpoints**

Add to `tests/test_auth.py`, inside a new test class:

```python
class TestJsonAuthEndpoints(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(self.db_path)

        os.environ['SECRET_KEY'] = 'test-secret-key'
        os.environ['THREAT_DB_PATH'] = self.db_path

        import importlib
        import src.dashboard.routes.api_threats as api_threats
        import src.dashboard.routes.api_stats as api_stats
        import src.dashboard.routes.api_analytics as api_analytics
        import src.dashboard.routes.api_notifications as api_notifications
        import src.dashboard.routes.api_ml as api_ml
        import src.dashboard.app as app_module

        importlib.reload(api_threats)
        importlib.reload(api_stats)
        importlib.reload(api_analytics)
        importlib.reload(api_notifications)
        importlib.reload(api_ml)
        importlib.reload(app_module)

        self.app_module = app_module
        self.app_module.app.config['TESTING'] = True
        self.client = self.app_module.app.test_client()

        from src.auth import hash_password
        self.app_module.db.create_user('jsonuser', 'json@example.com', hash_password('jsonpass123'))

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        os.environ.pop('SECRET_KEY', None)
        os.environ.pop('THREAT_DB_PATH', None)

    def test_json_login_success_returns_user(self):
        response = self.client.post('/api/auth/login', json={
            'username': 'jsonuser',
            'password': 'jsonpass123'
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['username'], 'jsonuser')

    def test_json_login_failure_returns_401(self):
        response = self.client.post('/api/auth/login', json={
            'username': 'jsonuser',
            'password': 'wrong'
        })
        self.assertEqual(response.status_code, 401)
        data = response.get_json()
        self.assertFalse(data['success'])

    def test_me_endpoint_requires_auth(self):
        response = self.client.get('/api/auth/me')
        self.assertEqual(response.status_code, 401)

    def test_me_endpoint_returns_user_when_logged_in(self):
        self.client.post('/api/auth/login', json={
            'username': 'jsonuser',
            'password': 'jsonpass123'
        })
        response = self.client.get('/api/auth/me')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data['data']['username'], 'jsonuser')

    def test_json_logout_clears_session(self):
        self.client.post('/api/auth/login', json={
            'username': 'jsonuser',
            'password': 'jsonpass123'
        })
        logout_response = self.client.post('/api/auth/logout')
        self.assertEqual(logout_response.status_code, 200)

        me_response = self.client.get('/api/auth/me')
        self.assertEqual(me_response.status_code, 401)

    def test_system_info_endpoint(self):
        self.client.post('/api/auth/login', json={
            'username': 'jsonuser',
            'password': 'jsonpass123'
        })
        response = self.client.get('/api/system-info')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('version', data['data'])
        self.assertIn('database_type', data['data'])
        self.assertIn('rules_loaded', data['data'])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `set SECRET_KEY=test && python -m pytest tests/test_auth.py::TestJsonAuthEndpoints -v`
Expected: FAIL with 404s (routes don't exist yet).

- [ ] **Step 3: Add `get_system_info` to `DatabaseManager`**

In `src/database/db_manager.py`, add this method after `get_conversations_for_user` (added in Plan 3 Task 4):

```python
    def get_system_info(self, rules_loaded: int = 0) -> Dict[str, Any]:
        """
        Get basic system info for the settings page.

        Args:
            rules_loaded: Number of detection rules currently loaded (caller-supplied,
                since DatabaseManager doesn't own rule loading)

        Returns:
            Dictionary with version, database_type, rules_loaded
        """
        return {
            'version': '1.2.0',
            'database_type': 'sqlite',
            'rules_loaded': rules_loaded,
        }

```

- [ ] **Step 4: Replace the Jinja2 `/login` route with JSON auth endpoints, and add `/api/system-info`**

In `src/dashboard/app.py`, replace the entire `/login` and `/logout` route block:

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page and authentication handler"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        user = db.get_user_by_username(username)
        if user and verify_password(user['password_hash'], password):
            session['username'] = username
            db.update_last_login(username)
            next_url = request.args.get('next') or url_for('index')
            return redirect(next_url)

        return render_template('login.html', error='Invalid username or password'), 401

    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    """Log the current user out"""
    session.pop('username', None)
    return redirect(url_for('login'))
```

with:

```python
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """JSON login endpoint for the SPA"""
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    user = db.get_user_by_username(username)
    if user and verify_password(user['password_hash'], password):
        session['username'] = username
        db.update_last_login(username)
        return jsonify({'success': True, 'data': {'username': username}})

    return jsonify({'success': False, 'error': 'Invalid username or password'}), 401


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    """JSON logout endpoint for the SPA"""
    session.pop('username', None)
    return jsonify({'success': True})


@app.route('/api/auth/me')
def api_me():
    """Return the currently authenticated user, or 401 if not logged in"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Authentication required'}), 401
    return jsonify({'success': True, 'data': {'username': session['username']}})


@app.route('/api/system-info')
@login_required
def api_system_info():
    """Get basic system info for the settings page"""
    try:
        info = db.get_system_info(rules_loaded=len(rules_data.get('rules', [])))
        return jsonify({'success': True, 'data': info})
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
```

- [ ] **Step 5: Remove the now-obsolete `@login_required` page routes that rendered Jinja2 templates**

In `src/dashboard/app.py`, delete these five route functions entirely (they will be replaced by client-side React Router routes in Task 4 — the SPA's catch-all route added in Step 6 below serves `index.html` for these paths instead):

```python
@app.route('/')
@login_required
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/threats')
@login_required
def threats_page():
    """Threats list page"""
    return render_template('threats.html')

@app.route('/analytics')
@login_required
def analytics_page():
    """Analytics and reports page"""
    return render_template('analytics.html')

@app.route('/assistant')
@login_required
def assistant_page():
    """AI Security Assistant page"""
    return render_template('assistant.html')

@app.route('/settings')
@login_required
def settings_page():
    """Settings and configuration page"""
    return render_template('settings.html')
```

- [ ] **Step 6: Add a catch-all static-serving route for the built SPA**

In `src/dashboard/app.py`, add this near the top of the file, right after the Flask app + CORS + SocketIO setup block (before the backend module initialization):

```python
FRONTEND_DIST = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'frontend', 'dist')
```

Then, at the very end of the file, immediately before the `if __name__ == '__main__':` block, add:

```python
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_spa(path):
    """
    Serve the built React SPA for any non-API route.

    In development, the frontend runs on its own Vite dev server (port 5173)
    and this route is never hit for page loads — only used when running the
    production build through Flask directly.
    """
    if path.startswith('api/') or path.startswith('socket.io'):
        return jsonify({'success': False, 'error': 'Not found'}), 404

    full_path = os.path.join(FRONTEND_DIST, path)
    if path and os.path.exists(full_path) and os.path.isfile(full_path):
        return send_from_directory(FRONTEND_DIST, path)

    index_path = os.path.join(FRONTEND_DIST, 'index.html')
    if not os.path.exists(index_path):
        return jsonify({
            'success': False,
            'error': 'Frontend build not found. Run `npm run build` in the frontend/ directory.'
        }), 503

    return send_from_directory(FRONTEND_DIST, 'index.html')
```

Add `send_from_directory` to the Flask import at the top of the file:

```python
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_from_directory
```

- [ ] **Step 7: Run the new auth tests**

Run: `set SECRET_KEY=test && python -m pytest tests/test_auth.py -v`
Expected: All PASS, including the new `TestJsonAuthEndpoints` tests.

- [ ] **Step 8: Run the full backend test suite to check for regressions from removing the Jinja2 routes**

Run: `set SECRET_KEY=test && python -m pytest tests/ -v --tb=short 2>&1 | tail -60`

Expected: `tests/test_dashboard_api.py` should still pass (it tests `/api/*` routes, not the removed page routes). If any test references the removed `index`/`threats_page`/etc. routes or `render_template`, fix or remove that specific test — check with `grep -rn "render_template\|url_for('index')\|url_for('threats_page')" tests/` first to see if anything needs updating.

- [ ] **Step 9: Commit**

```bash
git add src/dashboard/app.py src/database/db_manager.py tests/test_auth.py
git commit -m "feat: convert Flask auth routes to JSON API, add system-info endpoint and SPA static serving"
```

---

### Task 4: Core app shell — routing, auth state, layout (Sidebar, TopBar, ProtectedRoute)

**Files:**
- Modify: `frontend/src/App.tsx`, `frontend/src/main.tsx`
- Create: `frontend/src/hooks/useAuth.ts`
- Create: `frontend/src/components/ProtectedRoute.tsx`
- Create: `frontend/src/components/layout/Sidebar.tsx`
- Create: `frontend/src/components/layout/TopBar.tsx`
- Create: `frontend/src/components/layout/AppLayout.tsx`
- Create: `frontend/src/components/ConnectionStatus.tsx`
- Create: `frontend/src/pages/LoginPage.tsx`

- [ ] **Step 1: Set up React Query provider in `main.tsx`**

Replace the full contents of `frontend/src/main.tsx` with:

```tsx
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter } from 'react-router-dom'
import App from './App.tsx'
import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5000,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
```

- [ ] **Step 2: Write the `useAuth` hook**

Create `frontend/src/hooks/useAuth.ts`:

```typescript
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '@/lib/api';

export function useAuth() {
  const queryClient = useQueryClient();

  const { data: user, isLoading, isError } = useQuery({
    queryKey: ['auth', 'me'],
    queryFn: api.auth.me,
    retry: false,
  });

  const loginMutation = useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      api.auth.login(username, password),
    onSuccess: (data) => {
      queryClient.setQueryData(['auth', 'me'], data);
    },
  });

  const logoutMutation = useMutation({
    mutationFn: api.auth.logout,
    onSuccess: () => {
      queryClient.setQueryData(['auth', 'me'], undefined);
      queryClient.clear();
    },
  });

  return {
    user,
    isAuthenticated: !isError && !!user,
    isLoading,
    login: loginMutation.mutateAsync,
    loginError: loginMutation.error as ApiError | null,
    isLoggingIn: loginMutation.isPending,
    logout: logoutMutation.mutateAsync,
  };
}
```

- [ ] **Step 3: Write the `ProtectedRoute` component**

Create `frontend/src/components/ProtectedRoute.tsx`:

```tsx
import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

export function ProtectedRoute() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
```

- [ ] **Step 4: Write the `LoginPage`**

Create `frontend/src/pages/LoginPage.tsx`:

```tsx
import { useState, FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { login, isLoggingIn, loginError } = useAuth();
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    try {
      await login({ username, password });
      navigate('/', { replace: true });
    } catch {
      // loginError is already surfaced via useAuth's mutation state
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Threat Advisor Login</CardTitle>
          <CardDescription>Sign in to access the security dashboard</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            {loginError && (
              <div className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                {loginError.message}
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoFocus
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <Button type="submit" className="w-full" disabled={isLoggingIn}>
              {isLoggingIn ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 5: Write the `ConnectionStatus` component**

Create `frontend/src/components/ConnectionStatus.tsx`:

```tsx
import { useEffect, useState } from 'react';
import { socket } from '@/lib/socket';

export function ConnectionStatus() {
  const [connected, setConnected] = useState(socket.connected);

  useEffect(() => {
    const onConnect = () => setConnected(true);
    const onDisconnect = () => setConnected(false);

    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);

    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
    };
  }, []);

  return (
    <div className="flex items-center gap-2 rounded-md bg-muted px-3 py-2 text-sm">
      <span
        className={`h-2 w-2 rounded-full ${connected ? 'bg-green-500' : 'bg-yellow-500'} animate-pulse`}
      />
      <span className="text-muted-foreground">{connected ? 'Connected' : 'Connecting...'}</span>
    </div>
  );
}
```

- [ ] **Step 6: Write the `Sidebar` component**

Create `frontend/src/components/layout/Sidebar.tsx`:

```tsx
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, ShieldAlert, LineChart, Bot, Settings, ShieldCheck } from 'lucide-react';
import { ConnectionStatus } from '@/components/ConnectionStatus';
import { cn } from '@/lib/utils';

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/threats', label: 'Threats', icon: ShieldAlert },
  { to: '/analytics', label: 'Analytics', icon: LineChart },
  { to: '/assistant', label: 'AI Assistant', icon: Bot },
  { to: '/settings', label: 'Settings', icon: Settings },
];

export function Sidebar() {
  return (
    <nav className="fixed left-0 top-0 flex h-screen w-64 flex-col border-r bg-card">
      <div className="flex items-center gap-3 border-b p-6">
        <ShieldCheck className="h-8 w-8 text-primary" />
        <h2 className="text-lg font-bold">CyberGuard</h2>
      </div>

      <ul className="flex-1 space-y-1 p-4">
        {navItems.map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-md px-4 py-2.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-accent-foreground',
                  isActive && 'bg-primary text-primary-foreground hover:bg-primary hover:text-primary-foreground'
                )
              }
            >
              <Icon className="h-5 w-5" />
              <span>{label}</span>
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="border-t p-4">
        <ConnectionStatus />
      </div>
    </nav>
  );
}
```

- [ ] **Step 7: Write the `TopBar` component**

Create `frontend/src/components/layout/TopBar.tsx`:

```tsx
import { ReactNode } from 'react';
import { LogOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/hooks/useAuth';

interface TopBarProps {
  title: string;
  description: string;
  actions?: ReactNode;
}

export function TopBar({ title, description, actions }: TopBarProps) {
  const { user, logout } = useAuth();

  return (
    <header className="flex items-center justify-between border-b bg-card px-8 py-6">
      <div>
        <h1 className="text-2xl font-bold">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <div className="flex items-center gap-3">
        {actions}
        {user && (
          <div className="flex items-center gap-3 border-l pl-3">
            <span className="text-sm text-muted-foreground">{user.username}</span>
            <Button variant="ghost" size="icon" onClick={() => logout()} title="Log out">
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        )}
      </div>
    </header>
  );
}
```

- [ ] **Step 8: Write the `AppLayout` component**

Create `frontend/src/components/layout/AppLayout.tsx`:

```tsx
import { Outlet } from 'react-router-dom';
import { Sidebar } from './Sidebar';

export function AppLayout() {
  return (
    <div className="min-h-screen bg-background">
      <Sidebar />
      <main className="ml-64">
        <Outlet />
      </main>
    </div>
  );
}
```

- [ ] **Step 9: Write `App.tsx` with the full route tree (placeholder pages for now, real pages built in Tasks 5-8)**

Replace the full contents of `frontend/src/App.tsx` with:

```tsx
import { Routes, Route } from 'react-router-dom';
import { ProtectedRoute } from '@/components/ProtectedRoute';
import { AppLayout } from '@/components/layout/AppLayout';
import LoginPage from '@/pages/LoginPage';
import DashboardPage from '@/pages/DashboardPage';
import ThreatsPage from '@/pages/ThreatsPage';
import AnalyticsPage from '@/pages/AnalyticsPage';
import AssistantPage from '@/pages/AssistantPage';
import SettingsPage from '@/pages/SettingsPage';

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/threats" element={<ThreatsPage />} />
          <Route path="/analytics" element={<AnalyticsPage />} />
          <Route path="/assistant" element={<AssistantPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Route>
    </Routes>
  );
}

export default App;
```

- [ ] **Step 10: Create placeholder page components so the app compiles (real implementations in Tasks 5-8)**

Create `frontend/src/pages/DashboardPage.tsx`:
```tsx
export default function DashboardPage() {
  return <div className="p-8">Dashboard (placeholder)</div>;
}
```

Create `frontend/src/pages/ThreatsPage.tsx`:
```tsx
export default function ThreatsPage() {
  return <div className="p-8">Threats (placeholder)</div>;
}
```

Create `frontend/src/pages/AnalyticsPage.tsx`:
```tsx
export default function AnalyticsPage() {
  return <div className="p-8">Analytics (placeholder)</div>;
}
```

Create `frontend/src/pages/AssistantPage.tsx`:
```tsx
export default function AssistantPage() {
  return <div className="p-8">Assistant (placeholder)</div>;
}
```

Create `frontend/src/pages/SettingsPage.tsx`:
```tsx
export default function SettingsPage() {
  return <div className="p-8">Settings (placeholder)</div>;
}
```

- [ ] **Step 11: Delete the default Vite template files no longer needed**

Run: `rm -f frontend/src/App.css` (the default Vite template's CSS file, superseded by Tailwind).

Also remove the default Vite logo assets: `rm -f frontend/src/assets/react.svg` and check `frontend/public/vite.svg` — leave `public/vite.svg` for now, or replace it with a shield icon in Task 9 (favicon polish).

- [ ] **Step 12: Verify the app compiles and runs**

Run: `cd frontend && npx tsc --noEmit`
Expected: No errors.

Run: `npm run dev` in the background, then check it started on port 5173 with no console errors. Stop the dev server after confirming.

- [ ] **Step 13: Commit**

```bash
cd ..
git add frontend/src
git commit -m "feat: add app shell (routing, auth, sidebar/topbar layout, login page)"
```

---

### Task 5: Dashboard page (stats, charts, recent threats, scan/monitor controls)

**Files:**
- Create: `frontend/src/hooks/useStats.ts`
- Create: `frontend/src/hooks/useSystemMetrics.ts`
- Create: `frontend/src/hooks/useSocket.ts`
- Create: `frontend/src/components/StatCard.tsx`
- Create: `frontend/src/components/SeverityBadge.tsx`
- Create: `frontend/src/components/ThreatTable.tsx`
- Modify: `frontend/src/pages/DashboardPage.tsx`

- [ ] **Step 1: Write the `useSocket` hook that wires Socket.IO events into React Query cache invalidation**

Create `frontend/src/hooks/useSocket.ts`:

```typescript
import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { socket } from '@/lib/socket';

export function useSocket() {
  const queryClient = useQueryClient();

  useEffect(() => {
    socket.connect();

    function handleNewThreats(data: { count: number }) {
      toast('New threats detected', {
        description: `${data.count} new threat(s) found`,
      });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['threats'] });
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
    }

    function handleSystemMetrics(data: unknown) {
      queryClient.setQueryData(['system-metrics-live'], data);
    }

    socket.on('new_threats', handleNewThreats);
    socket.on('system_metrics', handleSystemMetrics);

    return () => {
      socket.off('new_threats', handleNewThreats);
      socket.off('system_metrics', handleSystemMetrics);
      socket.disconnect();
    };
  }, [queryClient, toast]);
}
```

- [ ] **Step 2: Write `useStats` and `useSystemMetrics` hooks**

Create `frontend/src/hooks/useStats.ts`:

```typescript
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useStats() {
  return useQuery({
    queryKey: ['stats'],
    queryFn: api.stats.get,
    refetchInterval: 10000,
  });
}
```

Create `frontend/src/hooks/useSystemMetrics.ts`:

```typescript
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useSystemMetrics() {
  return useQuery({
    queryKey: ['system-metrics'],
    queryFn: api.systemMetrics.get,
    refetchInterval: 5000,
  });
}
```

- [ ] **Step 3: Write the `SeverityBadge` component**

Create `frontend/src/components/SeverityBadge.tsx`:

```tsx
import { cn } from '@/lib/utils';

const severityStyles: Record<string, string> = {
  critical: 'bg-red-600/15 text-red-500 border-red-600/30',
  high: 'bg-orange-600/15 text-orange-500 border-orange-600/30',
  medium: 'bg-amber-500/15 text-amber-500 border-amber-500/30',
  low: 'bg-blue-500/15 text-blue-500 border-blue-500/30',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  const style = severityStyles[normalized] ?? 'bg-muted text-muted-foreground border-border';

  return (
    <span className={cn('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize', style)}>
      {severity}
    </span>
  );
}
```

- [ ] **Step 4: Write the `StatCard` component**

Create `frontend/src/components/StatCard.tsx`:

```tsx
import { LucideIcon } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface StatCardProps {
  label: string;
  value: number | string;
  icon: LucideIcon;
  colorClass: string;
}

export function StatCard({ label, value, icon: Icon, colorClass }: StatCardProps) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-6">
        <div className={cn('flex h-12 w-12 items-center justify-center rounded-lg', colorClass)}>
          <Icon className="h-6 w-6" />
        </div>
        <div>
          <div className="text-2xl font-bold">{value}</div>
          <div className="text-sm text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 5: Write the shared `ThreatTable` component**

Create `frontend/src/components/ThreatTable.tsx`:

```tsx
import { Threat } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ShieldCheck } from 'lucide-react';

function formatDetectedAt(detectedAt: string): string {
  try {
    return new Date(detectedAt).toLocaleString();
  } catch {
    return detectedAt;
  }
}

interface ThreatTableProps {
  threats: Threat[];
  onRowClick?: (threat: Threat) => void;
}

export function ThreatTable({ threats, onRowClick }: ThreatTableProps) {
  if (threats.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
        <ShieldCheck className="h-10 w-10" />
        <p>No threats detected. System is secure.</p>
      </div>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Severity</TableHead>
          <TableHead>Threat Name</TableHead>
          <TableHead>Category</TableHead>
          <TableHead>Risk Score</TableHead>
          <TableHead>Detected</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {threats.map((threat) => (
          <TableRow
            key={threat.id}
            className={onRowClick ? 'cursor-pointer' : undefined}
            onClick={() => onRowClick?.(threat)}
          >
            <TableCell><SeverityBadge severity={threat.severity} /></TableCell>
            <TableCell className="font-medium">{threat.threat_name}</TableCell>
            <TableCell>{threat.category}</TableCell>
            <TableCell>{threat.risk_score.toFixed(2)}</TableCell>
            <TableCell className="text-muted-foreground">{formatDetectedAt(threat.detected_at)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
```

Note: uses `threat.detected_at`, NOT `threat.timestamp` — this is the exact bug that existed in the old `main.js:240` (`formatTimestamp(threat.timestamp)`), fixed here from the start since the TypeScript `Threat` interface (Task 2) doesn't even have a `timestamp` field, so using it would be a compile error, not a silent runtime bug.

- [ ] **Step 6: Write the full `DashboardPage`**

Replace the full contents of `frontend/src/pages/DashboardPage.tsx` with:

```tsx
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, RefreshCw, Play, Square } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { StatCard } from '@/components/StatCard';
import { ThreatTable } from '@/components/ThreatTable';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
import { useStats } from '@/hooks/useStats';
import { useSystemMetrics } from '@/hooks/useSystemMetrics';
import { useSocket } from '@/hooks/useSocket';
import { api } from '@/lib/api';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

export default function DashboardPage() {
  useSocket();
  const queryClient = useQueryClient();
  const [monitoring, setMonitoring] = useState(false);

  const { data: stats, isLoading: statsLoading } = useStats();
  const { data: metrics } = useSystemMetrics();

  const { data: threats, isLoading: threatsLoading } = useQuery({
    queryKey: ['threats', { limit: 10 }],
    queryFn: () => api.threats.list({ limit: 10 }),
  });

  const { data: timeline } = useQuery({
    queryKey: ['timeline', 24],
    queryFn: () => api.timeline.hourly(24),
  });

  const scanMutation = useMutation({
    mutationFn: api.scan.start,
    onSuccess: (data) => {
      toast.success('Scan complete', { description: data.message });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['threats'] });
      queryClient.invalidateQueries({ queryKey: ['timeline'] });
    },
    onError: (error: Error) => {
      toast.error('Scan failed', { description: error.message });
    },
  });

  const monitorMutation = useMutation({
    mutationFn: () => (monitoring ? api.monitoring.stop() : api.monitoring.start()),
    onSuccess: () => {
      setMonitoring(!monitoring);
      toast.success(monitoring ? 'Monitoring stopped' : 'Monitoring started');
    },
  });

  const bySeverity = stats?.by_severity ?? {};

  return (
    <div>
      <TopBar
        title="Security Dashboard"
        description="Real-time threat monitoring and analysis"
        actions={
          <>
            <Button onClick={() => scanMutation.mutate()} disabled={scanMutation.isPending}>
              <RefreshCw className={`mr-2 h-4 w-4 ${scanMutation.isPending ? 'animate-spin' : ''}`} />
              Run Scan
            </Button>
            <Button variant={monitoring ? 'destructive' : 'outline'} onClick={() => monitorMutation.mutate()}>
              {monitoring ? <Square className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
              {monitoring ? 'Stop Monitoring' : 'Start Monitoring'}
            </Button>
          </>
        }
      />

      <div className="space-y-6 p-8">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {statsLoading ? (
            Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-24" />)
          ) : (
            <>
              <StatCard label="Critical Threats" value={bySeverity.critical ?? 0} icon={AlertOctagon} colorClass="bg-red-600/15 text-red-500" />
              <StatCard label="High Severity" value={bySeverity.high ?? 0} icon={AlertCircle} colorClass="bg-orange-600/15 text-orange-500" />
              <StatCard label="Medium Severity" value={bySeverity.medium ?? 0} icon={AlertTriangle} colorClass="bg-amber-500/15 text-amber-500" />
              <StatCard label="Low Severity" value={bySeverity.low ?? 0} icon={Info} colorClass="bg-blue-500/15 text-blue-500" />
            </>
          )}
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Threat Timeline (24h)</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeline ?? []}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                <XAxis dataKey="time" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="high" stroke="#ea580c" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="medium" stroke="#f59e0b" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="low" stroke="#3b82f6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">CPU Usage</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.cpu_percent?.toFixed(1) ?? '0.0'}%</CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Memory Usage</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.memory_percent?.toFixed(1) ?? '0.0'}%</CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Network Connections</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.network_connections ?? 0}</CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">Active Processes</CardTitle></CardHeader>
            <CardContent className="text-2xl font-bold">{metrics?.process_count ?? 0}</CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>Recent Threats</CardTitle>
          </CardHeader>
          <CardContent>
            {threatsLoading ? <Skeleton className="h-48" /> : <ThreatTable threats={threats ?? []} />}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
```

- [ ] **Step 7: Add sonner's `Toaster` component to the app root so `toast(...)` calls actually render**

In `frontend/src/App.tsx`, add the import and component:

```tsx
import { Toaster } from '@/components/ui/sonner';
```

And inside the returned JSX, wrap the `<Routes>` with a fragment and add `<Toaster />` after it:

```tsx
  return (
    <>
      <Routes>
        {/* ...existing routes... */}
      </Routes>
      <Toaster />
    </>
  );
```

- [ ] **Step 8: Verify TypeScript compiles**

Run: `cd frontend && npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 9: Manual smoke test with the real backend running**

This requires both servers running. In one terminal:
```bash
cd ..
set SECRET_KEY=test-secret-for-local-run
python src/dashboard/app.py
```
In another terminal:
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in a browser (do not do this automatically — this step requires the user to visually confirm, since launching a GUI-visible dev server is exactly the kind of action that should be confirmed with the user first per this project's established working style. Describe what you did and ask the user to check it, rather than declaring success yourself).

- [ ] **Step 10: Commit**

```bash
cd ..
git add frontend/src
git commit -m "feat: implement dashboard page with live stats, timeline chart, system metrics, scan/monitor controls"
```

---

### Task 6: Threats page (filterable list + detail dialog) and Assistant page (chat UI)

**Files:**
- Create: `frontend/src/hooks/useThreats.ts`
- Create: `frontend/src/components/ThreatDetailDialog.tsx`
- Modify: `frontend/src/pages/ThreatsPage.tsx`
- Modify: `frontend/src/pages/AssistantPage.tsx`

- [ ] **Step 1: Write `useThreats` hook with filter state**

Create `frontend/src/hooks/useThreats.ts`:

```typescript
import { useQuery } from '@tanstack/react-query';
import { api } from '@/lib/api';

export function useThreats(hours: number) {
  return useQuery({
    queryKey: ['threats', { hours, limit: 100 }],
    queryFn: () => api.threats.list({ hours, limit: 100 }),
  });
}
```

- [ ] **Step 2: Write the `ThreatDetailDialog` component**

Create `frontend/src/components/ThreatDetailDialog.tsx`:

```tsx
import { Threat } from '@/types';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog';

interface ThreatDetailDialogProps {
  threat: Threat | null;
  onClose: () => void;
}

export function ThreatDetailDialog({ threat, onClose }: ThreatDetailDialogProps) {
  return (
    <Dialog open={!!threat} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-lg">
        {threat && (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                {threat.threat_name}
                <SeverityBadge severity={threat.severity} />
              </DialogTitle>
              <DialogDescription>{threat.category}</DialogDescription>
            </DialogHeader>
            <div className="space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <div className="text-muted-foreground">Risk Level</div>
                  <div className="font-medium">{threat.risk_level}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Risk Score</div>
                  <div className="font-medium">{threat.risk_score.toFixed(2)}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Detected</div>
                  <div className="font-medium">{new Date(threat.detected_at).toLocaleString()}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Status</div>
                  <div className="font-medium capitalize">{threat.status}</div>
                </div>
              </div>
              {threat.description && (
                <div>
                  <div className="text-muted-foreground">Description</div>
                  <p>{threat.description}</p>
                </div>
              )}
              {threat.advisory && (
                <div className="rounded-md border bg-muted/50 p-3">
                  <div className="font-medium">{threat.advisory.title}</div>
                  <p className="mt-1 text-muted-foreground">{threat.advisory.description}</p>
                </div>
              )}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
```

- [ ] **Step 3: Write the full `ThreatsPage`**

Replace the full contents of `frontend/src/pages/ThreatsPage.tsx` with:

```tsx
import { useMemo, useState } from 'react';
import { TopBar } from '@/components/layout/TopBar';
import { ThreatTable } from '@/components/ThreatTable';
import { ThreatDetailDialog } from '@/components/ThreatDetailDialog';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { useThreats } from '@/hooks/useThreats';
import { Threat } from '@/types';
import { Search } from 'lucide-react';

const severityFilters = ['all', 'critical', 'high', 'medium', 'low'];

export default function ThreatsPage() {
  const [hours, setHours] = useState(24);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedThreat, setSelectedThreat] = useState<Threat | null>(null);

  const { data: threats, isLoading } = useThreats(hours);

  const filtered = useMemo(() => {
    if (!threats) return [];
    return threats.filter((t) => {
      const matchesSeverity = severityFilter === 'all' || t.severity.toLowerCase() === severityFilter;
      const matchesSearch = !search || t.threat_name.toLowerCase().includes(search.toLowerCase());
      return matchesSeverity && matchesSearch;
    });
  }, [threats, severityFilter, search]);

  return (
    <div>
      <TopBar
        title="Threat Management"
        description="View and manage detected security threats"
        actions={
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search threats..."
              className="w-64 pl-8"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        }
      />

      <div className="space-y-4 p-8">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex gap-2">
            {severityFilters.map((f) => (
              <Button
                key={f}
                size="sm"
                variant={severityFilter === f ? 'default' : 'outline'}
                onClick={() => setSeverityFilter(f)}
                className="capitalize"
              >
                {f}
              </Button>
            ))}
          </div>

          <Select value={String(hours)} onValueChange={(v) => setHours(Number(v))}>
            <SelectTrigger className="w-48">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="24">Last 24 hours</SelectItem>
              <SelectItem value="168">Last 7 days</SelectItem>
              <SelectItem value="720">Last 30 days</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <Card>
          <CardContent className="p-0">
            {isLoading ? (
              <div className="p-6"><Skeleton className="h-64" /></div>
            ) : (
              <ThreatTable threats={filtered} onRowClick={setSelectedThreat} />
            )}
          </CardContent>
        </Card>
      </div>

      <ThreatDetailDialog threat={selectedThreat} onClose={() => setSelectedThreat(null)} />
    </div>
  );
}
```

- [ ] **Step 4: Write the full `AssistantPage`**

Replace the full contents of `frontend/src/pages/AssistantPage.tsx` with:

```tsx
import { useState, KeyboardEvent, useRef, useEffect } from 'react';
import { Bot, Send, ShieldCheck, Trash2 } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from 'sonner';
import { ChatMessage } from '@/types';

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
```

- [ ] **Step 5: Verify TypeScript compiles**

Run: `cd frontend && npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 6: Commit**

```bash
cd ..
git add frontend/src
git commit -m "feat: implement threats page (filter/search/detail dialog) and assistant chat page"
```

---

### Task 7: Analytics page (trend/category/risk charts + summary stats)

**Files:**
- Modify: `frontend/src/pages/AnalyticsPage.tsx`

- [ ] **Step 1: Write the full `AnalyticsPage`**

Replace the full contents of `frontend/src/pages/AnalyticsPage.tsx` with:

```tsx
import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { api } from '@/lib/api';
import {
  BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

const CATEGORY_COLORS = ['#4f46e5', '#06b6d4', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'];
const RISK_COLORS: Record<string, string> = {
  Critical: '#dc2626',
  High: '#ea580c',
  Medium: '#f59e0b',
  Low: '#3b82f6',
};

const periods = [
  { label: '24 Hours', value: 1 },
  { label: '7 Days', value: 7 },
  { label: '30 Days', value: 30 },
];

export default function AnalyticsPage() {
  const [days, setDays] = useState(7);

  const { data: dailyTimeline, isLoading: timelineLoading } = useQuery({
    queryKey: ['analytics-timeline', days],
    queryFn: () => api.timeline.daily(days),
  });

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['stats', 'analytics', days],
    queryFn: () => api.stats.get(),
  });

  const categoryData = useMemo(
    () => Object.entries(stats?.by_category ?? {}).map(([name, value]) => ({ name, value })),
    [stats]
  );

  const severityData = useMemo(
    () =>
      Object.entries(stats?.by_severity ?? {}).map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
      })),
    [stats]
  );

  const mostCommonCategory = useMemo(() => {
    if (categoryData.length === 0) return '-';
    return categoryData.reduce((max, c) => (c.value > max.value ? c : max), categoryData[0]).name;
  }, [categoryData]);

  return (
    <div>
      <TopBar title="Security Analytics" description="Comprehensive threat analysis and insights" />

      <div className="space-y-6 p-8">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Threat Trends Over Time</CardTitle>
            <div className="flex gap-2">
              {periods.map((p) => (
                <Button key={p.value} size="sm" variant={days === p.value ? 'default' : 'outline'} onClick={() => setDays(p.value)}>
                  {p.label}
                </Button>
              ))}
            </div>
          </CardHeader>
          <CardContent className="h-80">
            {timelineLoading ? (
              <Skeleton className="h-full" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dailyTimeline ?? []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                  <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#4f46e5" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader><CardTitle>Threat Categories</CardTitle></CardHeader>
            <CardContent className="h-64">
              {statsLoading ? <Skeleton className="h-full" /> : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={categoryData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                      {categoryData.map((_, i) => (
                        <Cell key={i} fill={CATEGORY_COLORS[i % CATEGORY_COLORS.length]} />
                      ))}
                    </Pie>
                    <Legend />
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle>Risk Level Distribution</CardTitle></CardHeader>
            <CardContent className="h-64">
              {statsLoading ? <Skeleton className="h-full" /> : (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={50} outerRadius={80}>
                      {severityData.map((entry, i) => (
                        <Cell key={i} fill={RISK_COLORS[entry.name] ?? '#94a3b8'} />
                      ))}
                    </Pie>
                    <Legend />
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </div>

        <Card>
          <CardHeader><CardTitle>Summary Statistics</CardTitle></CardHeader>
          <CardContent className="grid grid-cols-2 gap-6 sm:grid-cols-4">
            <div>
              <div className="text-sm text-muted-foreground">Total Threats</div>
              <div className="text-2xl font-bold">{stats?.total_threats ?? 0}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Active Critical</div>
              <div className="text-2xl font-bold">{stats?.active_critical ?? 0}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Most Common</div>
              <div className="text-2xl font-bold">{mostCommonCategory}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground">Time Window</div>
              <div className="text-2xl font-bold">{stats?.time_window_hours ?? 24}h</div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
```

Note: this deliberately does NOT fabricate a "Detection Rate" percentage the way the old `analytics.html` hardcoded `100%` — the real `/api/analytics/detection-rate` endpoint (fixed in Plan 1 Task 6) returns threats-per-hour, not a percentage, and there's no ground truth for "how many real threats existed vs. were caught" to compute a meaningful detection rate percentage. Showing "Time Window" instead is honest about what data is actually available, consistent with this rework's overall principle of not inventing fake data.

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd frontend && npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
cd ..
git add frontend/src/pages/AnalyticsPage.tsx
git commit -m "feat: implement analytics page with trend/category/risk charts"
```

---

### Task 8: Settings page (real system info + notification recipient management)

**Files:**
- Modify: `frontend/src/pages/SettingsPage.tsx`

- [ ] **Step 1: Write the full `SettingsPage`**

Replace the full contents of `frontend/src/pages/SettingsPage.tsx` with:

```tsx
import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Mail, Plus, Trash2, Send, Database, Info } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { toast } from 'sonner';
import { api } from '@/lib/api';

export default function SettingsPage() {
  const [newEmail, setNewEmail] = useState('');
  const queryClient = useQueryClient();

  const { data: systemInfo, isLoading: infoLoading } = useQuery({
    queryKey: ['system-info'],
    queryFn: api.system.info,
  });

  const { data: notificationStatus, isLoading: notifLoading } = useQuery({
    queryKey: ['notifications', 'status'],
    queryFn: api.notifications.status,
  });

  const addRecipientMutation = useMutation({
    mutationFn: (email: string) => api.notifications.addRecipient(email),
    onSuccess: () => {
      setNewEmail('');
      queryClient.invalidateQueries({ queryKey: ['notifications', 'status'] });
      toast.success('Recipient added');
    },
    onError: (error: Error) => toast.error('Failed to add recipient', { description: error.message }),
  });

  const removeRecipientMutation = useMutation({
    mutationFn: (email: string) => api.notifications.removeRecipient(email),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications', 'status'] });
      toast.success('Recipient removed');
    },
  });

  const testNotificationMutation = useMutation({
    mutationFn: api.notifications.sendTest,
    onSuccess: () => toast.success('Test notification sent'),
    onError: (error: Error) => toast.error('Failed to send test', { description: error.message }),
  });

  return (
    <div>
      <TopBar title="System Settings" description="View system information and manage notification recipients" />

      <div className="grid grid-cols-1 gap-6 p-8 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Database className="h-5 w-5" /> System Information</CardTitle>
            <CardDescription>Read-only system details</CardDescription>
          </CardHeader>
          <CardContent>
            {infoLoading ? (
              <Skeleton className="h-32" />
            ) : (
              <dl className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <dt className="text-muted-foreground">Version</dt>
                  <dd className="font-medium">{systemInfo?.version}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Database</dt>
                  <dd className="font-medium capitalize">{systemInfo?.database_type}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Rules Loaded</dt>
                  <dd className="font-medium">{systemInfo?.rules_loaded}</dd>
                </div>
              </dl>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Mail className="h-5 w-5" /> Email Notifications</CardTitle>
            <CardDescription>
              Status: {notifLoading ? '...' : notificationStatus?.status === 'enabled' ? 'Enabled' : 'Disabled'}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {notifLoading ? (
              <Skeleton className="h-32" />
            ) : (
              <>
                <div className="space-y-2">
                  {(notificationStatus?.recipients ?? []).length === 0 && (
                    <p className="text-sm text-muted-foreground">No recipients configured</p>
                  )}
                  {(notificationStatus?.recipients ?? []).map((email) => (
                    <div key={email} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                      <span>{email}</span>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeRecipientMutation.mutate(email)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>

                <div className="flex gap-2">
                  <Input
                    placeholder="Enter email address..."
                    value={newEmail}
                    onChange={(e) => setNewEmail(e.target.value)}
                  />
                  <Button
                    onClick={() => newEmail && addRecipientMutation.mutate(newEmail)}
                    disabled={addRecipientMutation.isPending}
                  >
                    <Plus className="h-4 w-4" />
                  </Button>
                </div>

                <Button variant="outline" className="w-full" onClick={() => testNotificationMutation.mutate()}>
                  <Send className="mr-2 h-4 w-4" /> Send Test Notification
                </Button>
              </>
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Info className="h-5 w-5" /> About Monitoring Configuration</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Scan intervals, CPU/memory thresholds, and detection rules are configured via{' '}
              <code className="rounded bg-muted px-1.5 py-0.5">config/config.yaml</code> and{' '}
              <code className="rounded bg-muted px-1.5 py-0.5">config/rules.json</code> on the server.
              Editing these values from the web UI is not yet supported.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
```

Note: this deliberately does not add fake "Save Settings"/"Reset to Defaults" buttons for monitoring thresholds (the old `settings.html` had these but they were never wired to any backend logic — clicking them did nothing). Being upfront that config lives in YAML/JSON files server-side is more honest than a rewrite that looks functional but silently does nothing on click, matching this project's established principle of not inventing fake functionality.

- [ ] **Step 2: Verify TypeScript compiles**

Run: `cd frontend && npx tsc --noEmit`
Expected: No errors.

- [ ] **Step 3: Commit**

```bash
cd ..
git add frontend/src/pages/SettingsPage.tsx
git commit -m "feat: implement settings page with real system info and notification recipient management"
```

---

### Task 9: Production build integration, favicon, cleanup of old Jinja2/vanilla-JS frontend

**Files:**
- Modify: `frontend/index.html` (title, favicon)
- Create: `frontend/public/favicon.svg`
- Delete: `src/dashboard/templates/*.html`, `src/dashboard/static/`
- Modify: `.gitignore` (ensure `frontend/dist/` is ignored — it's a build artifact)

- [ ] **Step 1: Set the page title and add a favicon matching the old shield icon**

Create `frontend/public/favicon.svg` with the same shield icon used in the old templates:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"><path fill="#6366f1" d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.777 11.777 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.24.829.24s.548-.108.829-.24a7.159 7.159 0 0 0 1.048-.625 11.775 11.775 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.541 1.541 0 0 0-1.044-1.263 62.467 62.467 0 0 0-2.887-.87C9.843.266 8.69 0 8 0zm0 5a1.5 1.5 0 0 1 .5 2.915l.385 1.99a.5.5 0 0 1-.491.595h-.788a.5.5 0 0 1-.49-.595l.384-1.99A1.5 1.5 0 0 1 8 5z"/></svg>
```

Edit `frontend/index.html`, updating the `<head>`:

```html
<!doctype html>
<html lang="en" class="dark">
  <head>
    <meta charset="UTF-8" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CyberGuard - Threat Advisor</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

Run: `rm -f frontend/public/vite.svg` (no longer referenced).

- [ ] **Step 2: Add `frontend/dist/` to `.gitignore`**

Run: `grep -n "frontend/dist\|^dist$" .gitignore`

If no match, append to the repo-root `.gitignore`:
```
frontend/dist/
```

- [ ] **Step 3: Build the production bundle and verify it works served through Flask**

Run:
```bash
cd frontend
npm run build
```
Expected: `frontend/dist/` created with `index.html`, `assets/*.js`, `assets/*.css`.

Run (from repo root):
```bash
cd ..
set SECRET_KEY=test-secret-for-local-run
python src/dashboard/app.py
```

Verify by fetching (not opening a browser — this is a scriptable check, safe to run without confirmation):
```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/
```
Expected: `200` (since `serve_spa` falls through to `index.html` for the root path, which Flask should serve even for unauthenticated users at the HTTP level — the React app itself handles the redirect to `/login` client-side once it loads and calls `/api/auth/me`).

Stop the Flask server after this check.

- [ ] **Step 4: Delete the old Jinja2 templates and vanilla-JS static assets**

Run:
```bash
rm -rf src/dashboard/templates
rm -rf src/dashboard/static
```

Note: `src/dashboard/templates/login.html` is included in this deletion since Task 3 already converted the login flow to a JSON API — nothing references `render_template` anymore. Verify with:
```bash
grep -rn "render_template" src/dashboard/app.py
```
Expected: no matches. If any remain, they indicate a route this plan missed — stop and investigate before deleting the templates directory (re-create it from git if you already deleted it: `git checkout -- src/dashboard/templates`).

- [ ] **Step 5: Remove the now-unused `render_template` import if nothing else uses it**

Run: `grep -n "render_template" src/dashboard/app.py`

If truly zero matches remain (confirmed in Step 4), edit `src/dashboard/app.py`'s Flask import line to remove `render_template`:

Old:
```python
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_from_directory
```

New:
```python
from flask import Flask, jsonify, request, session, redirect, url_for, send_from_directory
```

- [ ] **Step 6: Run the full backend test suite one final time**

Run: `set SECRET_KEY=test-secret-for-local-run && python -m pytest tests/ -v --tb=short 2>&1 | tail -60`
Expected: All PASS. If any test imports or references `render_template`, `login.html`, or the deleted static files, fix that specific test.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: wire up production build serving, remove obsolete Jinja2 templates and vanilla-JS static assets"
```

---

### Task 10: Documentation — update README and add frontend dev instructions

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a "Frontend Development" section to README.md**

After the existing `## 🚀 Quick Start` section, add:

```markdown
## 🎨 Frontend Development

The web dashboard is a React + TypeScript SPA in `frontend/`, talking to the Flask backend as a pure JSON API.

### Development (hot-reload)
```bash
# Terminal 1: backend API
set SECRET_KEY=<your-secret>
python src/dashboard/app.py

# Terminal 2: frontend dev server (proxies /api and /socket.io to Flask)
cd frontend
npm install
npm run dev
```
Open http://localhost:5173

### Production build
```bash
cd frontend
npm run build
```
This outputs static files to `frontend/dist/`, which Flask serves automatically when you run `python src/dashboard/app.py` — no separate frontend server needed in production.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document frontend development and build workflow"
```

---

## Plan Complete

This plan replaces the server-rendered Jinja2/vanilla-JS dashboard with a React + TypeScript + Vite SPA styled with Tailwind CSS and shadcn/ui, covering all 6 pages (login, dashboard, threats, analytics, assistant, settings) with typed API calls, React Query caching, real-time Socket.IO updates, and session-cookie auth preserved end-to-end. The old Jinja2 templates and vanilla JS are deleted only after the new frontend is built and verified working. Settings and Analytics pages deliberately show only real, backend-verified data rather than reproducing the old pages' non-functional placeholder UI (unwired save buttons, hardcoded "100%" detection rate).
