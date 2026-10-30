"""
SecureX Attack Tester - a separate desktop window for testing SecureX.

Each button runs one harmless scenario from simulator.py (loopback-only
network activity, dummy files in a temporary sandbox folder, a renamed copy
of ping.exe). Start monitoring in the SecureX dashboard, then click a button
and watch the Threats page.

Run:  python attacker/attacker_app.py
"""

import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import simulator  # noqa: E402

BG = '#141518'
PANEL = '#1d1f23'
FG = '#e7e8ea'
MUTED = '#9aa0a6'
ACCENT = '#3fb6a8'
DANGER = '#e5534b'

EXPECTED = {
    'process': 'Suspicious Process Execution',
    'backdoor': 'Unusual Port Connection',
    'portscan': 'Excessive Network Connections',
    'ransomware': 'Possible ransomware-like behaviour',
    'bruteforce': 'Failed logins (Audit page)',
    'cpu': 'Excessive CPU Usage',
}


# Put on the log queue by a worker thread when its scenario finishes; Tk may
# only be touched from the main thread, so drain_log handles it there.
FINISHED = object()


class AttackTesterApp:
    def __init__(self, root):
        self.root = root
        self.lines = queue.Queue()
        self.running = 0
        self.buttons = []
        simulator.log_sink = self.lines.put

        root.title('SecureX Attack Tester')
        root.configure(bg=BG)
        root.geometry('760x620')
        root.minsize(640, 520)

        style = ttk.Style(root)
        style.theme_use('clam')
        style.configure('TFrame', background=BG)
        style.configure('Panel.TFrame', background=PANEL)
        style.configure('TLabel', background=BG, foreground=FG, font=('Segoe UI', 10))
        style.configure('Muted.TLabel', background=BG, foreground=MUTED, font=('Segoe UI', 9))
        style.configure('PanelMuted.TLabel', background=PANEL, foreground=MUTED, font=('Segoe UI', 9))
        style.configure('PanelName.TLabel', background=PANEL, foreground=FG, font=('Segoe UI Semibold', 10))
        style.configure('Title.TLabel', background=BG, foreground=FG, font=('Segoe UI Semibold', 15))
        style.configure('Run.TButton', background=PANEL, foreground=FG, borderwidth=1, padding=(12, 4))
        style.map('Run.TButton', background=[('active', '#2a2d33'), ('disabled', PANEL)],
                  foreground=[('disabled', '#5f6368')])
        style.configure('All.TButton', background=ACCENT, foreground='#0b0c0e',
                        font=('Segoe UI Semibold', 10), padding=(14, 6))
        style.map('All.TButton', background=[('active', '#4fc8ba'), ('disabled', '#2b4f4b')])

        outer = ttk.Frame(root, padding=16)
        outer.pack(fill='both', expand=True)

        ttk.Label(outer, text='SecureX Attack Tester', style='Title.TLabel').pack(anchor='w')
        ttk.Label(outer, style='Muted.TLabel', text=(
            'Harmless test activity for SecureX. Start monitoring in the dashboard first. '
            'Network traffic stays on 127.0.0.1 and everything is cleaned up afterwards.'
        ), wraplength=700, justify='left').pack(anchor='w', pady=(2, 12))

        settings = ttk.Frame(outer)
        settings.pack(fill='x', pady=(0, 10))
        ttk.Label(settings, text='Hold (seconds)').pack(side='left')
        self.hold = tk.IntVar(value=45)
        tk.Spinbox(settings, from_=10, to=300, increment=5, width=5, textvariable=self.hold,
                   bg=PANEL, fg=FG, buttonbackground=PANEL, relief='flat',
                   insertbackground=FG).pack(side='left', padx=(6, 18))
        ttk.Label(settings, text='Dashboard URL').pack(side='left')
        self.url = tk.StringVar(value='http://127.0.0.1:5000')
        tk.Entry(settings, textvariable=self.url, width=26, bg=PANEL, fg=FG, relief='flat',
                 insertbackground=FG).pack(side='left', padx=(6, 0))

        grid = ttk.Frame(outer)
        grid.pack(fill='x')
        for index, (name, (_, description)) in enumerate(simulator.SCENARIOS.items()):
            card = ttk.Frame(grid, style='Panel.TFrame', padding=10)
            card.grid(row=index // 2, column=index % 2, sticky='nsew', padx=4, pady=4)
            ttk.Label(card, text=name, style='PanelName.TLabel').grid(row=0, column=0, sticky='w')
            ttk.Label(card, text=description, style='PanelMuted.TLabel',
                      wraplength=240).grid(row=1, column=0, sticky='w')
            ttk.Label(card, text=f'Expect: {EXPECTED[name]}', style='PanelMuted.TLabel',
                      wraplength=240).grid(row=2, column=0, sticky='w', pady=(2, 0))
            button = ttk.Button(card, text='Run', style='Run.TButton',
                                command=lambda n=name: self.start([n]))
            button.grid(row=0, column=1, rowspan=3, padx=(8, 0))
            card.columnconfigure(0, weight=1)
            self.buttons.append(button)
        grid.columnconfigure(0, weight=1, uniform='col')
        grid.columnconfigure(1, weight=1, uniform='col')

        actions = ttk.Frame(outer)
        actions.pack(fill='x', pady=(10, 8))
        self.all_button = ttk.Button(actions, text='Run all at once', style='All.TButton',
                                     command=lambda: self.start(simulator.DEFAULT_ALL))
        self.all_button.pack(side='left')
        self.buttons.append(self.all_button)
        self.status = ttk.Label(actions, text='Idle', style='Muted.TLabel')
        self.status.pack(side='left', padx=12)
        ttk.Button(actions, text='Clear log', style='Run.TButton',
                   command=lambda: self.log.delete('1.0', 'end')).pack(side='right')

        self.log = ScrolledText(outer, height=12, bg='#0e0f11', fg=FG, relief='flat',
                                insertbackground=FG, font=('Consolas', 9), wrap='word')
        self.log.pack(fill='both', expand=True)
        self.log.tag_configure('error', foreground=DANGER)
        self.log.tag_configure('step', foreground=ACCENT)

        root.protocol('WM_DELETE_WINDOW', self.on_close)
        self.root.after(100, self.drain_log)

    def start(self, names):
        try:
            hold = max(5, int(self.hold.get()))
        except (tk.TclError, ValueError):
            hold = 45
        url = self.url.get().strip() or 'http://127.0.0.1:5000'
        self.set_running(len(names))
        for name in names:
            threading.Thread(target=self.run_one, args=(name, hold, url), daemon=True).start()

    def run_one(self, name, hold, url):
        try:
            simulator.run_scenario(name, hold, url)
        finally:
            self.lines.put(FINISHED)

    def set_running(self, count):
        self.running += count
        for button in self.buttons:
            button.state(['disabled'])
        self.status.configure(text=f'Running {self.running} scenario(s)... watch the SecureX Threats page')

    def finish_one(self):
        self.running -= 1
        if self.running <= 0:
            self.running = 0
            for button in self.buttons:
                button.state(['!disabled'])
            self.status.configure(text='Done. Check the Dashboard / Threats / Audit pages.')

    def drain_log(self):
        while not self.lines.empty():
            line = self.lines.get()
            if line is FINISHED:
                self.finish_one()
                continue
            tag = 'error' if ('failed' in line or 'skipped' in line) else ('step' if '>>' in line else '')
            self.log.insert('end', line + '\n', tag)
            self.log.see('end')
        self.root.after(100, self.drain_log)

    def on_close(self):
        # Scenarios clean up in "finally" blocks; closing mid-run only skips the
        # remaining hold time, so tidy the ransomware sandbox if it is still there.
        sandbox = simulator._documents_dir() / simulator.SANDBOX_NAME
        if sandbox.exists():
            import shutil
            shutil.rmtree(sandbox, ignore_errors=True)
        self.root.destroy()


def main():
    root = tk.Tk()
    AttackTesterApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
