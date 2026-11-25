# PyCentric Design System (`design.md` / `PYC-DESIGN-SYS-01`)

**Applies To**:
- `flutter_client/` (Mobile, Tablet, Desktop, Web Companion UI)
- `src/tui/` (`ratatui` + `crossterm` Terminal Dashboard)
- `src/dashboard/` (Embedded Web Control Plane Dashboard)

## 1. Design Token Pipeline (W3C Style Dictionary)

- Source of truth: `tokens/design-tokens.json` (W3C Design Tokens format).
- Generated Flutter tokens: `flutter_client/lib/src/app_tokens.g.dart`.
- **No Raw Color Literals**: Feature widgets and `theme.dart` must bind to `CordonDesignTokens` / `Theme.of(context).colorScheme` rather than ad-hoc `Colors.*` or `Color(0x...)` literals.

## 2. Tri-Theme Parity & Contrast (`GL-06`)

All three theme presets (`CordonThemePreset.light`, `CordonThemePreset.dark`, `CordonThemePreset.highContrast`) must maintain parity:
- **Light & Dark**: Material 3 semantic `ColorScheme` derived from `CordonDesignTokens.brandSeed`.
- **High-Contrast (`>= 7:1` WCAG AAA)**: Pure black scaffold, high-luminance yellow primary, white on-surface.
- **Touch Targets**: Minimum `48x48dp` (`minButtonSize = Size(48, 48)`) on all interactive buttons.

## 3. 4-Tier Adaptive Layout & Safe Navigation

- `CordonDashboardScaffold` (`flutter_client/lib/main.dart`) adapts across:
  - Compact (`< 600dp`): `NavigationBar` / `BottomNavigationBar`
  - Medium (`600-839dp`): `NavigationRail`
  - Expanded (`840-1199dp`) & Ultra-Wide (`>= 1200dp`): Docked / collapsible `NavigationDrawer` sidebar with `1440dp` max-content container.
- **PyCentric Attribution**: `CordonAttributionFooter` renders on every dashboard pane.
- **Localization**: 100% `.arb` strings (`en`, `af`, `zu` in `flutter_client/lib/l10n/`).

## 4. Layout, Directionality & Typography Rules (Section 11)

- Strict `4px`/`8px` spacing grid; prefer `gap` / `spacing` over child margins.
- Logical directional properties only (`EdgeInsetsDirectional`, `ps-*`/`pe-*`); avoid `EdgeInsets.only(left/right)`.
- Use `FontFeature.tabularFigures()` / `tabular-nums` on numeric counters, latency metrics, and timestamps.
- Zero Unicode em-dashes or en-dashes (`[INV-TYPOGRAPHY]`).

## 5. Terminal UI (`src/tui/`) Rules

- Support `NO_COLOR=1` and `TERM=dumb` graceful degradation.
- Maintain `2:1` horizontal-to-vertical cell padding proportions and clean box-drawing borders (`ratatui::widgets::Borders`).
- Support both Arrow keys and Vim navigation (`j`/`k`, `q` to quit).
