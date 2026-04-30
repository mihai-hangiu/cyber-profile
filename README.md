# Stefan Hangiu — Cyber Security Portfolio

Personal presentation site: CTF competitions, profile, skills.

**Live:** `https://[username].github.io/[repo-name]/`

---

## File structure

```
├── index.html              # Complete site (HTML + CSS + JS)
├── competitions.json       # Your competitions — edit this
├── PROJECT_CONTEXT.md      # Full technical documentation
└── README.md               # This file
```

---

## Quick edit

**Add a competition** → edit `competitions.json`:
```json
{
    "name":               "Competition Name",
    "date":               "2025-06-01",
    "duration":           "1-2 Jun 2025",
    "organizer":          "Organizer",
    "position":           3,
    "total_participants": 250,
    "competition_filter": "other",
    "is_final":           true,
    "__comments":         ""
}
```

**Edit profile** (name, about, skills, links) → `index.html`, `CONFIG` object inside `<script>`.

---

## Filter values for `competition_filter`

| Value    | Filter button |
|----------|---------------|
| `"unr"`  | UNR           |
| `"rocsc"`| RoCSC         |
| `"osc"`  | OSC           |
| `"other"`| Other         |

---

## Medal color thresholds

| Positions | Color  |
|-----------|--------|
| 1–5       | Gold   |
| 6–10      | Silver |
| 11–15     | Bronze |
| 16+       | Cyan   |

---

## Local development

```bash
python -m http.server 8080
# http://localhost:8080
```

> **Note:** `fetch()` does not work on `file://`. Always use a local server.

---

## Deploy to GitHub Pages

1. Create a new repository on GitHub (e.g. `ctf-profile`)
2. Push all files:
   ```bash
   git init
   git add .
   git commit -m "initial commit"
   git remote add origin https://github.com/[username]/ctf-profile.git
   git push -u origin main
   ```
3. Repository → **Settings → Pages → Source: main branch, / (root)**
4. Site available at `https://[username].github.io/ctf-profile/`

---

## competitions.json field reference

| Field                | Shown | Description                                      |
|----------------------|-------|--------------------------------------------------|
| `name`               | Yes   | Competition name                                 |
| `date`               | Yes   | Main date (YYYY-MM-DD)                           |
| `duration`           | Yes   | Full date range as string                        |
| `organizer`          | Yes   | Organizer(s)                                     |
| `position`           | Yes   | Overall rank                                     |
| `total_participants` | Yes   | Total participants                               |
| `competition_filter` | No*   | Filter key: unr / rocsc / osc / other            |
| `is_final`           | No**  | Counted in "Finals" stat card                    |
| `__comments`         | No    | Private notes, not shown on site                 |

*Used for filter buttons only.
**Only the count is shown, not the field value directly.
