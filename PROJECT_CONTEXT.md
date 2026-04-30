# PROJECT_CONTEXT.md — Stefan Hangiu Cyber Portfolio

## Purpose
Personal presentation site for **Stefan Hangiu**, 9th grade student (Math-Computer Science),
passionate about cybersecurity, ethical hacking, CTF, AI, and Linux.
Hosted on GitHub Pages (static: HTML + JS + JSON, no backend).

---

## File structure

```
stefan-hangiu-site/
├── index.html              # The entire site (HTML + CSS + JS)
├── competitions.json       # Competition data — edit this file
├── PROJECT_CONTEXT.md      # This file
└── README.md               # Deploy and editing instructions
```

> **Note:** `competitions.json` lives in the **same folder** as `index.html`.
> The site loads it via `fetch('competitions.json')`.

---

## How the site works

- **Single HTML file** with 3 simulated pages (JS-driven, no reload): `home`, `competitions`, `profile`.
- Competitions are loaded asynchronously from `competitions.json` via `fetch()`.
- **Responsive design** via a single HTML/CSS file with media queries — works on desktop and mobile without separate versions.
- Mobile hamburger menu appears below 768px width.
- All text (code, comments, UI labels) is in **English**.

---

## Editing profile data

Personal data (name, handle, tagline, about, skills, tools, timeline, links) is edited directly
in `index.html`, inside the `CONFIG` object in the `<script>` block at the bottom of the file.

```js
const CONFIG = {
    profile: {
        name:    "Stefan Hangiu",
        handle:  "@shx0",
        tagline: "Breaking things to understand them.",
        links: [
            { type: "github",  label: "GH", url: "https://github.com/shx0" },
            // ...
        ],
    },
    about:    [ "Paragraph 1...", "Paragraph 2..." ],
    skills:   [ "Web Exploitation", "Forensics", ... ],
    tools:    [ "Burp Suite", "Ghidra", ... ],
    timeline: [ { year: "2025", title: "Title", desc: "Description" }, ... ],
};
```

---

## competitions.json schema

Each entry in `competitions.json`:

| Field                | Type              | Shown on site  | Description                                                    |
|----------------------|-------------------|----------------|----------------------------------------------------------------|
| `name`               | string            | Yes            | Competition name                                               |
| `date`               | string YYYY-MM-DD | Yes            | Main date (first day or key day)                               |
| `duration`           | string            | Yes (subtitle) | Full date range, e.g. "15-17 Mar 2025"                         |
| `organizer`          | string            | Yes            | Organizer(s)                                                   |
| `position`           | number            | Yes            | Overall rank in the competition                                |
| `total_participants` | number            | Yes            | Total number of participants                                   |
| `competition_filter` | string            | No*            | Filter key: `unr` / `rocsc` / `osc` / `other`                 |
| `is_final`           | boolean           | No**           | true if this was a finals-stage participation                  |
| `__comments`         | string            | No             | Private notes — not displayed on site                          |

*Used for the filter buttons (All / UNR / RoCSC / OSC / Other).
**Counted in the "Finals" stat card on the competitions page.

### Filter values for `competition_filter`
- `"unr"`   — Unbreakable Romania
- `"rocsc"` — Romanian Cyber Security Challenge
- `"osc"`   — Olimpiada de Securitate Cibernetica (or similar OSC event)
- `"other"` — Everything else

---

## Stats bar (competitions page)

| Card         | Logic                                               |
|--------------|-----------------------------------------------------|
| Competitions | Total number of entries in `competitions.json`      |
| Finals       | Count of entries where `is_finals === true`         |
| Top 10       | Count where `position_overall <= 10`                |
| *(Top 3)*    | *Commented out — activate in `renderCompetitions()` when needed* |

---

## Medal color thresholds (rank badge on cards)

| CSS class | Positions | Color    |
|-----------|-----------|----------|
| `gold`    | 1–5       | #ffd600  |
| `silver`  | 6–10      | #b0bec5  |
| `bronze`  | 11–15     | #ff9100  |
| `other`   | 16+       | cyan     |

---

## Design

- **Theme:** Dark cyber / terminal green
- **Fonts:** Orbitron (display), Share Tech Mono (mono), Rajdhani (body)
- **Primary colors:** `#00ff88` (green), `#00e5ff` (cyan), `#ff3d5a` (red), `#ffd600` (gold)
- **Background effect:** Matrix rain canvas (binary/hex chars, low opacity)
- **Profile logo:** Animated cyber shield SVG with scan-line and glow-pulse effect
- **Competition cards:** Color-coded by position range (gold/silver/bronze/cyan)
- **Sub-ranks:** Shown on card only when `position_grade` or `position_school` are non-null

---

## GitHub Pages limitations

- No server-side code (no PHP, Python, Node.js).
- `fetch('competitions.json')` works on GitHub Pages (HTTPS, same-origin).
- **Warning:** `fetch()` does NOT work when opening `index.html` directly from the filesystem (`file://`).
  Always use a local server for development: `python -m http.server 8080`.
- External resources (Google Fonts) require internet access.

---

## Local development

```bash
# In the project directory:
python -m http.server 8080
# Open: http://localhost:8080
```

---

## Session history

| Session | Changes |
|---------|---------|
| #1 | Initial build. Migrated from `competitions.js` global to async JSON fetch. Shield SVG replaces rotating initials avatar. Added `position_grade`, `position_school`, `duration`, `notes` to JSON schema. Category badge removed from cards (kept in JSON for filtering). |
| #3 | JSON schema cleanup: removed `category`, `position_grade`, `position_school`; renamed `position_overall` → `position`, `totalParticipants` → `total_participants`, `is_finals` → `is_final`; added `__comments` (private notes field). Updated index.html to match. |
