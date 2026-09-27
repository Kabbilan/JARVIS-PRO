# SentraPixel frontend design system

The UI uses `frontend/src/design-system.css`, loaded after the existing screen styles in `main.jsx`. The stylesheet scopes component rules to `.soc-shell` and preserves current workflows.

## Colors

| Role | Hex |
| --- | --- |
| Canvas | `#07111f` |
| Surface | `#1a2332` |
| Raised surface | `#2d3e52` |
| Accent / info | `#00d9ff` |
| Accent deep | `#007da6` |
| Critical | `#ff0040` |
| Warning | `#ffb700` |
| Success | `#00ff41` |
| Primary text | `#e8f0f7` |
| Muted text | `#b5c9d7` |

Status text on dark backgrounds uses lighter variants to improve readability. Do not use saturated status colors directly for small text without checking contrast.

## Type and spacing

Headings and body use Inter when installed, then the system UI font stack. Metrics use JetBrains Mono when installed, then system monospace. No remote font fetch is required. Page titles scale from 26px on small screens to 48px on large screens; panel titles scale from 18px to 24px. Body content is generally 12–16px; compact data labels can be 10–11px where the existing table layout requires them.

The spacing base is 8px, with 16px gutters for compact layouts and 24px for desktop cards. The dashboard width caps at 1440px. Current screen grids retain their functional column arrangements and stack at 1300px, 900px, and 760px.

## Interaction patterns

Primary buttons use a cyan gradient; secondary actions use a cyan outline. Cards use translucent navy surfaces with cyan borders and soft shadows. Inputs show a visible cyan focus ring. Severity badges use distinct color, text, and borders. Page entry lasts 300ms; interactive hover lasts 200ms. Loading placeholders shimmer. `prefers-reduced-motion` disables animations and transitions.

## Accessibility checks

The shell includes a skip link, labeled navigation, active page state, labeled icon controls, visible keyboard focus, and reduced motion support. This is an implementation checklist, **not a WCAG audit certificate**. Verify every screen and breakpoint with a browser and keyboard, check text contrast on actual backgrounds, and test a screen reader before marking WCAG 2.1 AA as passed.

## Performance

Styles animate opacity and transforms for page entry and interactions. No font or icon package was added. Existing Lucide icons remain in use. Data fetching continues through the existing incident API cache.
