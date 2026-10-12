# renewhunt design brief

Reference object: a **Solari / split-flap railway departure board** (certificate renewals = departures; flaps flip to show days-left and READY / LATE / RISKY).

Metaphor: each scan finding is a departure row; severity is the signal lamp; the board header is the product name.

- Base: board charcoal `#1c2229` (blue-charcoal mid-dark — not certfan `#0b0b0c`, not packfence `#0a1628`, not actnode asphalt).
- Flap cream `#efe6d4`; amber bulb `#e8a017` (not packfence `#f4b942`, not actnode `#f2b705`); oxidized copper frame `#6a4e3b`; signal green READY `#3f8f6b`; signal red LATE `#c44536` (not toolsmoke `#c3271b`).
- Type: **Saira Extra Condensed** 600/700 (flap / departure letters) + **Newsreader** 400/600 (body) + **Space Mono** 400 (commands only). Self-hosted woff2 (OFL).
- Texture: subtle horizontal slot lines between flap rows (`repeating-linear-gradient`). No paper, no CRT scanlines, no metal brush, no 3D isometric.
- Rendering: CSS 3D flap flip (`rotateX`) on HTML board rows — not isometric, not hinge-open doors, not X-ray SVG.
- Layout: full-width departure board as hero; h1 is board header text `RENEWHUNT — DEPARTURES`; rows are scan findings that flip in; sections below are timetable panels.
- Motion: flap flip revealing READY / LATE / RISKY; rows stagger in. `prefers-reduced-motion`: show final state, no flip.
- Logo: single split-flap cell showing `43` (⅔ of 64) in Saira Extra Condensed on cream flap with charcoal frame; transparent bg; not a rounded app icon. Favicon = simplified 2-digit flap.
- Banned check: no dark+cyan/purple gradients, no gradient text, no glow, no glassmorphism, no left-copy/right-card hero, no 3-col feature cards, no Inter+mono SaaS template, no paper/stamp/typewriter.
