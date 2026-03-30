/*
 * ═══════════════════════════════════════════════════════════
 * COMPETITIONS DATA — Editeaza competitiile aici
 * ═══════════════════════════════════════════════════════════
 *
 * Structura unei competitii:
 * {
 *     name:              "Numele competitiei",
 *     date:              "2025-03-15",           // Format: YYYY-MM-DD
 *     position:          1,                      // Pozitia ocupata
 *     totalParticipants: 320,                    // Nr. total participanti
 *     organizer:         "Organizatorii",
 *     category:          "web"                   // web / forensics / crypto / reverse / pwn / general / misc
 * }
 *
 * Categorii disponibile:
 *   "web"       — Web Exploitation
 *   "forensics" — Forensics / DFIR
 *   "crypto"    — Cryptography
 *   "reverse"   — Reverse Engineering
 *   "pwn"       — Binary Exploitation / Pwn
 *   "general"   — General / Mixed CTF
 *   "misc"      — Miscellaneous / Altele
 *
 * ═══════════════════════════════════════════════════════════
 */

const COMPETITIONS_DATA = [
    {
        name: "Unbreakable Romania",
        date: "2025-03-15",
        position: 5,
        totalParticipants: 320,
        organizer: "Bit Sentinel & Orange Romania",
        category: "general"
    },
    {
        name: "CyberEdu CTF",
        date: "2025-02-10",
        position: 1,
        totalParticipants: 150,
        organizer: "CyberEdu",
        category: "web"
    },
    {
        name: "DefCamp CTF Quals",
        date: "2025-01-20",
        position: 12,
        totalParticipants: 500,
        organizer: "DefCamp",
        category: "general"
    },
    {
        name: "PicoCTF 2025",
        date: "2025-03-01",
        position: 3,
        totalParticipants: 8000,
        organizer: "Carnegie Mellon University",
        category: "general"
    },
    {
        name: "RoCSC Selection",
        date: "2024-11-05",
        position: 2,
        totalParticipants: 200,
        organizer: "DNSC & Cyberint",
        category: "forensics"
    },
    {
        name: "HTB University CTF",
        date: "2024-12-08",
        position: 8,
        totalParticipants: 1200,
        organizer: "Hack The Box",
        category: "pwn"
    },
    {
        name: "HTB University CTF dfhsdj fdsjfh dsfjdsf fsdf dsfdsfsdfsdfsd dsfjdsf fsdf dsfdsfsdfsdfsd",
        date: "2024-12-08",
        position: 8,
        totalParticipants: 1200,
        organizer: "Hack The Box",
        category: "pwn"
    },
    // ── Adauga mai multe competitii deasupra ──
];
