# Design

How every Licash app looks and speaks: the Android app, the wallet CLI,
and the operators' commands and dashboards. Read this before changing what
a person sees. The apps differ in medium, not in manners.

## Principles

1. **What they care about, first.** A wallet holder cares how much they
   have, how much of it is protected, what a payment costs and when it
   arrives. An operator cares whether the service is healthy, what it
   earned and what needs them. Lead with that; everything else waits.
2. **Little text.** A screen or an output says one thing. Prefer a number,
   a word or a short phrase to a sentence; never a paragraph where a label
   does.
3. **Details on request.** Explanations sit behind an (i), a sheet, a fold
   or a flag (`--json`, advanced mode, a detail page). Nothing is
   removed: it is one tap or one flag away, never in the way.
4. **Plain words.** No ids, hashes, block heights, ppm, notes or
   providers unless asked for (advanced mode, `--json`, a detail view).
   Times are spans (`about 2 hours`, `in 3 days`), not heights. Amounts
   are `12,345 sat`, digits grouped, the unit always said.
5. **Risk is never hidden.** What is not protected, what is on credit,
   what failed, what a test network's contract is worth (`Test only:
   protects nothing`), and what cannot be undone are always said, in
   words and not by color alone. Folding never hides them.
6. **One look.** The same thing looks and is named the same everywhere:
   one way to show a fact, a row, a state, a failure, a confirmation.
   Reuse the shared parts rather than restyling one screen.
7. **One obvious action.** Each screen has one main thing to do, in the
   primary color; a second, if any, is quieter beside or under it. What
   destroys is red and confirmed.
8. **Calm states.** Loading, empty and failed states are designed: a word
   for what is happening, nothing for what is empty unless it helps, and
   for a failure what failed (a title), why (a line) and what to do.
9. **A fee says what it is of.** Wherever a cost is shown, its share of
   the amount it is charged on is shown beside it: `12 sat · 0.24%` in
   the app, `10,000 + 12 sat (0.12%)` in a terminal. Two significant
   digits (`0.24%`, `1.2%`, `5%`, `12%`), `<0.01%` below that, nothing
   for no fee (the word `None` says it). A protection's price is a share
   of what it covers, and is itemized before it is paid: the hub's
   opening fee, its interest by the year on the part it funds (and on
   hers), her reserve, returned as notes, and her part, which is the rest
   of her coin and issued back to her: a coin is spent whole, and no change
   comes back from it. A fee known only as terms (`1 sat + 0.5%`, or
   `1 sat + 0.01% + 0.1 sat a note` at a hub that charges for the notes a
   payment makes) stays terms; a limit stays a limit (`Up to 21 sat ·
   0.21%`). Operator views retain their existing percentage precision
   (two decimals below 1%, otherwise one), but never round a nonzero fee
   to `0.00%`.
10. **Every tap answers.** The control tapped reacts at once, busy where
    it is or by changing the view, and cannot be tapped again while its
    work lasts. A wait says what is happening and, once it passes a few
    seconds, how long it has lasted. A sheet that starts work stays open
    on it until it ends, and shows the reason if it fails: never closed
    onto silence. Work that goes on without the owner (a contract being
    set up, a close in the background) shows where it stands on the page
    it belongs to. An outcome is seen and felt: a short haptic for done
    and another for failed, and a tick for a switch; not for every tap.

## Words

| Say | Not |
| --- | --- |
| Balance | Notes, holdings |
| Protected, Not protected | Covered by a contract, on credit (said only inside the (i)) |
| Protection | Contract, recovery contract (advanced mode aside) |
| Setting up, Confirming, Protecting / Live, Ending, Ended, Failed | Opening, funding, asserting |
| Hub, named by its host | URL, keyset, mint |
| Arrives in about 20 min | 2 blocks deep, confirmations |
| Fee, Total | Base + ppm, margin |
| On Bitcoin, over Lightning, in Licash | On-chain, L1, LN |
| Couldn't pay, Can't send on Bitcoin | Error, failed (alone) |
| Vault, only as the picture: the tour, the first funding, a step card | Vault for a protection's rows and states |

Core error reasons pass through `explain()` and `plain()` (Android,
`Format.kt`): a sentence, amounts grouped, swap providers unnamed.

## Android

Jetpack Compose; the shared parts are in `ui/Parts.kt` and the colors and
type in `ui/Theme.kt`. Use them; do not restyle a screen on its own.

- **Layout.** A screen is a `TopBar` (back, title, an (i) at most), then
  its subject: a big amount (`Figures` on Home, `Heading` elsewhere), then
  `Group`s of rows, then its buttons.
- **Rows.** `Entry` for something to open or a value (a chevron when it
  opens), `Line` for a fact, `Toggle` for on or off. A glyph on a tile
  only on a list's first page (Settings), and then on every row of it.
  A row that destroys is red text, no glyph.
- **Fees** are a `Line` with `share = share(fee, of)` (`Format.kt`), the
  share quieter after the amount, its own `tag-share`; in a sentence or
  an offer, `feeOf(fee, of)` (`12 sat · 0.24%`).
- **Group** cards of 20 dp corners; a title only when the page's title
  does not say it already.
- **Buttons.** `BigButton`: one primary (green), a quiet one in the same
  green tint, `danger` red for what cannot be undone. Small buttons are
  `FilledTonalButton`, which the theme tints the same.
- **Sheets** (`Sheet`, open whole) for what is read and left or one
  choice made: an (i)'s meaning, fees, a confirmation, a move. A screen
  for what is worked in: sending, receiving. No `AlertDialog`.
- **Explanations** behind `Info`, an (i) opening a sheet of one `Say`.
  `More` folds what few ask for, under a word.
- **Outcomes** of paying (`Outcome` in `ui/Send.kt`): a glyph in a disc
  (check, spinner, (i), warning), a title, a line, its buttons. Done,
  under way, a question and a failure all look alike.
- **States** in a glyph and a word (`Pill`, `Step`), never by color alone;
  progress as a bar or a timeline of steps.
- **Waiting.** `BigButton(busy = true)` makes a button its own wait: a
  spinner and its label, not tappable. `Waited` says the seconds. A sheet
  doing work is not `dismissable` unless the work goes on without it, and
  closes itself once the work is done.
- **Haptics** only through `Feel` (`ui/Feel.kt`): `confirm` and `reject`
  for outcomes (`Outcome` does both by itself) and a switch's tick
  (`Toggle` does it). Never on every tap, never alone: a haptic repeats
  what the screen says in words.
- **Announcing.** An outcome's title is a polite live region, so a screen
  reader says it. Not the seconds of a wait: they change too often.
- **Advanced mode** (`ui.developer`) adds the technical: blocks, notes,
  providers, ids, the light client's settings, the log. Basic mode never
  shows them.
- **One next step.** Home suggests at most one thing to do, as a card
  (`StepCard`, `ui/NextStep.kt`): a title, a line and its button. The
  rest of the screen stays the balance, its gauge and Receive and Send.
- **Pictures** are drawn in Compose (`ui/Drawings.kt`), the same shapes in
  both themes: flat in dark, outlined in light. No raster images.
- **Tests read tags.** Every view the end-to-end test reads or taps has a
  `testTag` (sheets set `testTagsAsResourceId`); change a tag only with
  `apps/e2e/tests/app.rs`.

## Terminal

The wallet CLI (`licash-wallet`), the hub and swap services
(`licash-hub`, `licash-swaps`) and their dashboards.

- **Output is for a person by default, `--json` for a program.** Human
  output may change; JSON, payment artifacts on stdout, exit codes (75
  for pending, 1 for errors) and the texts tests pin may not without
  changing their consumers in the same commit.
- **Lead with the answer.** A command prints its result first, in a line
   or a short aligned table: `12,345 sat` before how it was reached.
- **Summary first, literally.** `balance` does not list hubs; service
  `status` does not list transactions or internal note counts. `--details`
  reveals them (swaps also accepts `--swaps N`). Pending funds, losses,
  uncounted funds and delivery failures stay visible in the summary.
  Payment delivery to a mailbox, or kept at the hub, is not receipt by
  the recipient: only their acknowledgment through the hub is. Fee
  bounds are labeled `up to`, not presented as the exact price paid.
- **Aligned key-value lines** (`label  value`), labels in plain words,
  values right where they line up; amounts grouped with their unit
  (`10,000 + 12 sat` for an amount and its fee); fees as sat and a
  percentage (`1 sat + 0.1%`), never ppm; times as spans or UTC dates
  (`2026-11-15 13:05`), heights only where they are the deadline, labeled
  `block`; ids shortened (`a1b2c3d4…`) and only where they are needed to
  act on something.
- **Errors** are `error: what failed: why` on stderr, one line, with what
  to do when known. Progress and logs go to stderr too, never mixed into
   the result.
- **Diagnostics are requested, not endured.** Wallet dependency logs are
  off unless `--log` or `RUST_LOG` is set. Interactive payments say what
  they are doing before the network wait; redirected and JSON output has
  no progress decoration. Services retain warnings and concise lifecycle
  logs; raw configuration is debug detail, recoverable relay errors do not
  flood normal output. `--log json` retains structured service logging.
- **Color** only on a terminal, never carrying meaning alone: green for
  done or healthy, yellow for attention, red for failure, dim for
  secondary detail.
- **States** in a glyph and a word: `✓` healthy or done, `!` attention,
  `✗` failing, `–` idle. What needs attention is listed first.
- **Nothing cut.** Text too long for its place wraps under itself, or
  says less as a whole (a comparison dropped, a legend without its
  totals, `+2 more`, a title ending at a word in `…`): never a word cut
   in half.
  A table that cannot fit its columns becomes wrapped, labeled records.
  Never crop a number to fit: `1,010 sat` must not become `010 sat`.
  Scrolling still moves by record; wide terminals keep aligned columns.
- **Dashboards**: the overview page first (the few numbers that matter,
  then health beside one chart, then what happened), detail on the
  following pages, each chart on one page only; one accent color, one
  style of card, chart and table; empty and stale states said in words
  or left blank; no heights in the header; the key bar always at the
  bottom, `?` for the rest.
