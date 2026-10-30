import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  Activity, Bot, Download, FileSearch, FileWarning, Gauge, Link2, Lock, Mail, ScrollText, ShieldAlert, ShieldCheck,
  Siren, Workflow,
} from 'lucide-react';
import { GuardMark } from '@/components/GuardMark';
import { Button } from '@/components/ui/button';
import { api } from '@/lib/api';
import { useAuth } from '@/hooks/useAuth';

type FeatureStatus = 'Implemented' | 'Experimental';

const FEATURES: { icon: typeof Activity; title: string; body: string; status: FeatureStatus }[] = [
  {
    icon: Activity,
    title: 'Process and network monitoring',
    body: 'Watches running processes, CPU and memory use, open ports and outbound connections on the machine SecureX runs on.',
    status: 'Implemented',
  },
  {
    icon: ShieldAlert,
    title: 'Rule-based detection',
    body: 'Ten behaviour rules, covering suspicious processes, unusual ports, connection floods, privilege escalation and more, each with an advisory.',
    status: 'Implemented',
  },
  {
    icon: Gauge,
    title: 'Contextual risk scoring',
    body: 'Low to Critical, adjusted for how critical the device is, network exposure, privileged accounts and off-hours activity. Every adjustment is shown.',
    status: 'Implemented',
  },
  {
    icon: FileSearch,
    title: 'Unknown-threat detection',
    body: 'Learns what is normal on your computer, then flags processes that behave very differently as "unknown suspicious activity", showing what stood out.',
    status: 'Experimental',
  },
  {
    icon: FileWarning,
    title: 'Ransomware-like behaviour',
    body: 'Watches your Documents, Desktop and Pictures for bursts of file changes, mass renames to unusual extensions and ransom-note files.',
    status: 'Implemented',
  },
  {
    icon: Link2,
    title: 'Phishing URL check',
    body: 'Paste a link to check it for look-alike domains, hidden destinations and other phishing tricks, without ever opening it.',
    status: 'Implemented',
  },
  {
    icon: Bot,
    title: 'AI security assistant',
    body: 'Explains alerts in plain language using retrieved documentation and your own threat records, and flags uncertain answers. It cannot act on your system.',
    status: 'Implemented',
  },
  {
    icon: Siren,
    title: 'Human-approved response',
    body: 'High and Critical threats get proposals to suspend or end the process. Nothing runs until you approve it, and suspensions can be undone.',
    status: 'Implemented',
  },
  {
    icon: Mail,
    title: 'Email alerts',
    body: 'Alerts for the severities you choose, sent only to verified addresses, with duplicate suppression, retries and a delivery log.',
    status: 'Implemented',
  },
  {
    icon: ScrollText,
    title: 'Tamper-evident audit log',
    body: 'Logins, settings changes and every response decision are recorded in a hash chain you can verify from the dashboard.',
    status: 'Implemented',
  },
];

const STEPS = [
  ['Monitor', 'Collect process and connection telemetry locally.'],
  ['Detect', 'Match events against behaviour rules and, optionally, the anomaly model.'],
  ['Score', 'Assign a risk level and record why.'],
  ['Explain', 'Generate an advisory; ask the assistant for more detail.'],
  ['Respond', 'Alert you and propose containment for you to approve.'],
  ['Audit', 'Record every decision in the audit log.'],
];

const FAQ = [
  [
    'Is SecureX an antivirus?',
    'No. It does not scan files against malware signatures and it does not replace Microsoft Defender or another antivirus. It watches system behaviour and helps you understand and respond to what it finds.',
  ],
  [
    'Will it stop processes on its own?',
    'No. Containment is only proposed. A signed-in user must approve each action, and real execution is switched off by default, so approvals are recorded as dry runs until an administrator enables it.',
  ],
  [
    'Does it send my data anywhere?',
    'Not by default. Telemetry and threat history stay in a local SQLite database. Data leaves the machine only if you enable an external AI provider (your question plus the retrieved context) or email alerts.',
  ],
  [
    'Can it monitor other computers?',
    'Not yet. The dashboard shows the machine the SecureX server runs on. Enrolling and monitoring several devices is planned, not implemented.',
  ],
  [
    'How accurate is the anomaly model?',
    'No accuracy figures are published yet. The evaluation pipeline exists, but results will only be reported after it has been run on the real datasets, and they will describe offline flow data, not live monitoring.',
  ],
];

function formatSize(bytes: number) {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.ceil(bytes / 1024)} KB`;
}

function DownloadSection() {
  const { data, isLoading, isError } = useQuery({ queryKey: ['public-info'], queryFn: api.public.info });
  const release = data?.release;

  return (
    <section id="download" className="scroll-mt-20 border-t border-border py-20">
      <div className="mx-auto max-w-7xl px-6">
        <h2 className="text-2xl font-semibold tracking-tight">Download</h2>
        <div className="mt-8 grid gap-6 md:grid-cols-[3fr_2fr]">
          <div className="rounded-lg border border-border bg-card p-6">
            {isLoading ? (
              <p className="text-sm text-muted-foreground">Checking for a published release…</p>
            ) : isError ? (
              <p className="text-sm text-muted-foreground">Release information is unavailable right now.</p>
            ) : release ? (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-lg font-semibold">SecureX {release.version}</span>
                  <span
                    className={`rounded px-2 py-0.5 text-xs font-medium ${
                      release.status === 'stable' ? 'bg-success-bg text-success' : 'bg-warning-bg text-warning'
                    }`}
                  >
                    {release.status === 'stable' ? 'Stable' : 'Preview build'}
                  </span>
                </div>
                <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
                  <dt className="text-muted-foreground">Platform</dt><dd>{release.platform}</dd>
                  <dt className="text-muted-foreground">Released</dt><dd>{release.released_at}</dd>
                  <dt className="text-muted-foreground">File</dt><dd className="break-all">{release.file} ({formatSize(release.size_bytes)})</dd>
                  <dt className="text-muted-foreground">SHA-256</dt><dd className="break-all font-mono text-xs">{release.sha256}</dd>
                  <dt className="text-muted-foreground">Signature</dt><dd>Not code-signed. Windows SmartScreen may warn on first run.</dd>
                </dl>
                {release.notes.length > 0 && (
                  <ul className="mt-4 list-disc pl-5 text-sm text-muted-foreground">
                    {release.notes.map((note) => <li key={note}>{note}</li>)}
                  </ul>
                )}
                <Button asChild className="mt-6">
                  <a href={release.download_url}><Download className="mr-2 h-4 w-4" /> Download for Windows</a>
                </Button>
                <p className="mt-3 text-xs text-muted-foreground">
                  Verify the file before running it: <code>Get-FileHash .\{release.file}</code> in PowerShell
                  should print the SHA-256 above.
                </p>
              </>
            ) : (
              <>
                <span className="rounded bg-warning-bg px-2 py-0.5 text-xs font-medium text-warning">
                  No installer published yet
                </span>
                <p className="mt-4 text-sm text-muted-foreground">
                  SecureX {data?.app_version} is in development and has no published Windows build yet. You can run
                  it from source:
                </p>
                <pre className="mt-4 overflow-x-auto rounded-md bg-muted p-4 text-xs leading-relaxed">{`python -m venv venv
venv\\Scripts\\activate
pip install -r requirements.txt -r requirements-desktop.txt
cd frontend && npm install && npm run build && cd ..
python scripts/create_admin_user.py
python desktop_app.py`}</pre>
              </>
            )}
          </div>
          <div className="rounded-lg border border-border bg-card p-6 text-sm">
            <h3 className="font-semibold">System requirements</h3>
            <ul className="mt-3 space-y-1.5 text-muted-foreground">
              <li>Windows 11, 64-bit (the platform it is built and tested on)</li>
              <li>From source: Python 3.12 and Node.js 22 (the tested versions)</li>
              <li>Optional AI retrieval: about 100 MB for the embedding model on first use</li>
              <li>Optional: an SMTP account for email alerts, an API key for an external AI model</li>
            </ul>
            <h3 className="mt-6 font-semibold">Uninstall</h3>
            <p className="mt-2 text-muted-foreground">
              Close SecureX and delete its folder. Local data (database and logs) is in the app's <code>data</code> folder.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function LandingPage() {
  const { isAuthenticated } = useAuth();
  const dashboardLink = isAuthenticated ? '/' : '/login';

  return (
    <div className="min-h-screen bg-background text-foreground">
      <header className="sticky top-0 z-10 border-b border-border bg-background">
        <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
          <a href="#top" className="flex items-center gap-2">
            <GuardMark className="h-7 w-7 text-primary" />
            <span className="font-semibold tracking-tight">SecureX</span>
          </a>
          <nav className="hidden items-center gap-6 text-sm text-muted-foreground md:flex">
            <a href="#features" className="hover:text-foreground">Features</a>
            <a href="#how" className="hover:text-foreground">How it works</a>
            <a href="#privacy" className="hover:text-foreground">Security &amp; privacy</a>
            <a href="#download" className="hover:text-foreground">Download</a>
            <a href="#faq" className="hover:text-foreground">FAQ</a>
          </nav>
          <div className="flex items-center gap-2">
            {!isAuthenticated && (
              <Button asChild size="sm" variant="ghost">
                <Link to="/login">Sign in</Link>
              </Button>
            )}
            <Button asChild size="sm" variant={isAuthenticated ? 'outline' : 'default'}>
              <Link to={isAuthenticated ? '/' : '/signup'}>{isAuthenticated ? 'Open dashboard' : 'Sign up'}</Link>
            </Button>
          </div>
        </div>
      </header>

      <main id="top">
        <section className="mx-auto max-w-7xl px-8 py-24">
          <span className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground">
            Research prototype · not a replacement for antivirus
          </span>
          <h1 className="mt-6 max-w-4xl text-4xl font-semibold leading-tight tracking-tight md:text-6xl">
            Threat detection you can understand, with responses you approve.
          </h1>
          <p className="mt-6 max-w-3xl text-xl text-muted-foreground">
            SecureX monitors a Windows machine for suspicious behaviour, scores each finding in context, explains it in
            plain language, and proposes containment that runs only after you approve it.
          </p>
          <div className="mt-10 flex flex-wrap gap-3">
            <Button asChild size="lg">
              <a href="#download"><Download className="mr-2 h-4 w-4" /> Download for Windows</a>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link to={dashboardLink}>{isAuthenticated ? 'Open dashboard' : 'Sign in to the dashboard'}</Link>
            </Button>
            {!isAuthenticated && (
              <Button asChild size="lg" variant="ghost">
                <Link to="/signup">Create an account</Link>
              </Button>
            )}
          </div>
        </section>

        <section id="features" className="scroll-mt-20 border-t border-border py-20">
          <div className="mx-auto max-w-7xl px-6">
            <h2 className="text-2xl font-semibold tracking-tight">Features</h2>
            <p className="mt-2 text-muted-foreground">Each feature is labelled with its actual status.</p>
            <div className="mt-10 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {FEATURES.map(({ icon: Icon, title, body, status }) => (
                <div key={title} className="rounded-lg border border-border bg-card p-5">
                  <div className="flex items-start justify-between gap-3">
                    <Icon className="h-5 w-5 text-primary" />
                    <span
                      className={`rounded px-2 py-0.5 text-[11px] font-medium ${
                        status === 'Implemented' ? 'bg-success-bg text-success' : 'bg-info/15 text-info'
                      }`}
                    >
                      {status}
                    </span>
                  </div>
                  <h3 className="mt-3 font-medium">{title}</h3>
                  <p className="mt-1.5 text-sm text-muted-foreground">{body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="how" className="scroll-mt-20 border-t border-border py-20">
          <div className="mx-auto max-w-7xl px-6">
            <h2 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
              <Workflow className="h-6 w-6 text-primary" /> How it works
            </h2>
            <ol className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {STEPS.map(([title, body], index) => (
                <li key={title} className="rounded-lg border border-border p-5">
                  <div className="text-xs font-medium text-primary">Step {index + 1}</div>
                  <div className="mt-1 font-medium">{title}</div>
                  <p className="mt-1 text-sm text-muted-foreground">{body}</p>
                </li>
              ))}
            </ol>
            <div className="mt-10 grid gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-border bg-card p-5">
                <h3 className="font-medium">Rule-based detection</h3>
                <p className="mt-1.5 text-sm text-muted-foreground">
                  Rules describe known suspicious behaviour, such as a process imitating a system name or a connection
                  to a port favoured by remote-access tools. Matches are specific and explainable, but rules only find
                  what they describe.
                </p>
              </div>
              <div className="rounded-lg border border-border bg-card p-5">
                <h3 className="font-medium">Anomaly-based detection</h3>
                <p className="mt-1.5 text-sm text-muted-foreground">
                  An anomaly model learns what normal activity looks like and flags deviations. It can surface
                  unfamiliar behaviour, but an anomaly is not proof of an attack, so SecureX reports it as a score, not
                  a diagnosis.
                </p>
              </div>
            </div>
          </div>
        </section>

        <section id="privacy" className="scroll-mt-20 border-t border-border py-20">
          <div className="mx-auto max-w-7xl px-6">
            <h2 className="flex items-center gap-2 text-2xl font-semibold tracking-tight">
              <Lock className="h-6 w-6 text-primary" /> Security &amp; privacy
            </h2>
            <div className="mt-10 grid gap-4 md:grid-cols-2">
              <div className="rounded-lg border border-border p-5 text-sm">
                <h3 className="font-medium">What is collected</h3>
                <p className="mt-1.5 text-muted-foreground">
                  Process names, IDs, owning account and CPU/memory use, plus local and remote addresses and ports of
                  network connections. No keystrokes, file contents, browsing history or messages.
                </p>
              </div>
              <div className="rounded-lg border border-border p-5 text-sm">
                <h3 className="font-medium">Where it goes</h3>
                <p className="mt-1.5 text-muted-foreground">
                  Into a local database on the same machine. It is sent elsewhere only if you turn on an external AI
                  provider or email alerts, and emails exclude passwords, keys and file contents.
                </p>
              </div>
              <div className="rounded-lg border border-border p-5 text-sm">
                <h3 className="font-medium">Who can act</h3>
                <p className="mt-1.5 text-muted-foreground">
                  The dashboard requires sign-in. The AI assistant has no ability to run commands. Containment needs
                  explicit approval, re-checks its target and is recorded in the audit log.
                </p>
              </div>
              <div className="rounded-lg border border-border p-5 text-sm">
                <h3 className="flex items-center gap-1.5 font-medium">
                  <ShieldCheck className="h-4 w-4 text-primary" /> Known limitations
                </h3>
                <ul className="mt-1.5 list-disc space-y-1 pl-4 text-muted-foreground">
                  <li>No malware-signature scanning or threat feeds, so detections are never "confirmed".</li>
                  <li>No file quarantine; ransomware alerts cannot name the process that changed the files.</li>
                  <li>Monitors only the machine it runs on; no multi-device enrollment yet.</li>
                  <li>Risk multipliers are a documented heuristic, not a calibrated model.</li>
                  <li>Builds are not code-signed and there is no automatic updater.</li>
                </ul>
              </div>
            </div>
          </div>
        </section>

        <DownloadSection />

        <section id="faq" className="scroll-mt-20 border-t border-border py-20">
          <div className="mx-auto max-w-4xl px-6">
            <h2 className="text-2xl font-semibold tracking-tight">FAQ</h2>
            <div className="mt-8 space-y-3">
              {FAQ.map(([question, answer]) => (
                <details key={question} className="rounded-lg border border-border p-4">
                  <summary className="cursor-pointer font-medium">{question}</summary>
                  <p className="mt-2 text-sm text-muted-foreground">{answer}</p>
                </details>
              ))}
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-border py-10 text-sm text-muted-foreground">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6">
          <div className="flex items-center gap-2">
            <GuardMark className="h-5 w-5 text-primary" />
            SecureX · Adaptive Threat Detection &amp; Automated Response Platform
          </div>
          <div className="flex gap-5">
            <a href="#privacy" className="hover:text-foreground">Privacy</a>
            <a href="#faq" className="hover:text-foreground">FAQ</a>
            <Link to={dashboardLink} className="hover:text-foreground">Dashboard</Link>
          </div>
        </div>
        <p className="mx-auto mt-4 max-w-7xl px-6 text-xs">
          Documentation ships with the source in the <code>docs/</code> folder: setup, configuration, email alerts,
          governance and dataset evaluation.
        </p>
      </footer>
    </div>
  );
}
