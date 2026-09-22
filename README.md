# Secure the Office — version 3

A browser-based physical-security lesson tool. No installation, student account, backend or API key.

Written for **Pearson Level 3 AAQ BTEC National in Information Technology, Unit 2: Cyber Security
and Incident Management** — the externally assessed unit. Students design the physical security of
a small office, test it against incidents, and then answer exam-style questions about their own design.

## Run

Open `index.html` in a modern browser, or publish the repository root with GitHub Pages
(Settings → Pages → Deploy from a branch → main → / root). All asset paths are relative, so the
site works under `/physical/` or any other subdirectory.

## Where it sits in the specification

| Code | Content | How the tool covers it |
|---|---|---|
| A1.1.2 | Accidental or deliberate damage | Fire, flood, power-loss and overheating incidents; suppression, flood defence, UPS and cooling controls |
| A1.1.3 | Weak security measures and unsafe practices | Tailgating, unvetted contractors, opportunist theft, a leaver whose card still works |
| A1.1.4 | Accidental loss or disclosure of data | Media safe, secure-disposal procedure |
| A1.2.3 | Sabotage | After-hours vehicle incident, perimeter controls |
| A1.2.4 | Social engineering | Tailgating incident, ID badges, visitor procedure |
| A4 | Software and hardware security measures | The whole control catalogue: locks, card entry, biometrics, cages, CCTV, intruder detection |
| C1 | Internal policies | Seven operational procedures that incidents check alongside the equipment |

Each control, procedure, incident and exam question carries its specification code in the interface,
and the Mission report shows a coverage list built from what the student actually did.

## Student journey

1. **Research** two products from different suppliers for each technique, recording name, image,
   description, supplier link, price and price basis/date — then write which one they would buy and why.
   Each technique carries a built-in *Typical products and prices* reference: two generic product
   categories, the typical UK range for one unit and what the price needs to state. It is a starting
   point for the search, not evidence — nothing in it can be saved as a record.
2. **Deploy** products onto the office floorplan with a written justification for the zone and the supplier.
3. **Declare procedures** — visitor escorting, alarm response, key control, backups, disposal and so on.
   Procedures are charged to the same budget at an indicative annual cost, must be supported by equipment
   already in the design, and need a named owner.
4. **Test** against twelve incidents and use the debriefs to revise the design.
5. **Answer** eight exam-practice questions using the unit's command words, with indicative content to
   self-assess against.
6. **Evaluate** and print or save the mission report as a PDF.

## Example products

Every technique has a reference card in the research lab and inside the product form: what the two
common product categories are, what they each do and do not do, the typical UK price range for a
single unit, and what a credible price has to say (rating, capacity, whether install and VAT are
included). Students still have to find a real supplier page, price it and date it themselves — the
reference cannot be saved as a record. Prices well outside the range trigger a warning that asks
whether a unit has been confused with a system; it warns, it does not block.

The ranges are classroom estimates and go stale. They live in the `EXAMPLES` object in `app.js`,
one entry per technique — worth a look each September.

## Research requirement

Two modes, switchable in *Mission and lesson guide* or from the research lab:

- **Deployed techniques only** (default) — students compare two suppliers for each control they
  actually use. Research follows the design decision, which is how it works in practice, and keeps
  the workload to a couple of lessons.
- **All techniques** — two suppliers for all 18 techniques, 36 records. Use this if research breadth
  is the point of the lesson rather than the design.

## Control catalogue

- **Preventative** — door locks, card/fob entry, biometrics, barriers and bollards, controlled gate,
  cabinet or cage, device locks, flood defence, temperature control, power protection.
- **Detective** — CCTV, intruder detection.
- **Corrective** — fire suppression, gas suppression, media safe.
- **Directive** — security signage, ID badges.
- **Compensating** — standby cooling, with an explanation of the primary control it replaces.

## Procedures are not free

Ticking all seven costs £2,740 of the £14,000 budget, so procedures compete with equipment for the same
money — which is the trade-off exam question 8 asks students to evaluate.

Some procedures depend on equipment: alarm response needs CCTV or intruder detection; key control needs locks or an entry system; temperature changeover needs cooling. Evacuation planning does not depend on buying suppression equipment. A procedure with nothing behind it is charged for, flagged on the card and in the report, and
does **not** count when an incident is evaluated. Evacuation, backup rotation and secure disposal have no catalogue equipment dependency.

Every declared procedure needs a written owner — who does it, and how you would know it is actually
happening. That statement (at least 25 characters) is required for scenario credit and clearance, and appears on the report. The teacher must review its quality; length alone is not evidence of effectiveness.

## Incidents

Twelve deterministic scenarios: tailgating, after-hours vehicle, server-room intrusion, records store,
delivery entrance, laptop theft, a leaver's card still working, flood, office fire, server-room fire,
cooling failure and a mains power cut. Each checks control types, named zones and declared procedures,
and shows the specification code it is testing.

They are teaching feedback, not engineering predictions. Camera coverage, lock ratings, gas-system
suitability, flood heights, installation quality, price accuracy and product quality are not verified.
A control does not become effective because a student described it well — teacher discussion and
evidence evaluation remain central.

## Exam practice

Eight questions using the unit's command words — identify, describe, explain, evaluate — set against
the student's own design, with mark allocations and indicative content they can reveal to self-assess.
Self-awarded marks are for tracking only and appear on the printed report for the teacher to override.

## Scoring

15 XP per complete product record for a technique the student deploys; 25 per two-supplier comparison
with a written choice; 15 per deployment; 60 per incident fully addressed by the current design; 10 per
exam question answered; 10 per supported procedure with a named owner.

In deployed-only mode, product records for techniques that are never deployed earn nothing, and the meter is measured against
progress targets of 17 techniques and 27 placements (not a prescribed shopping list), so filling in forms
without building anything does not move the rank.

Repeated runs of an unchanged design do not stack XP. A result is invalidated only by a change to the
**effective design**: placing or removing a control, changing its declared capability, or changing whether a procedure is supported and owned. Price and budget changes affect affordability, not incident effectiveness. Recording a second supplier, editing a
description, reopening a save file and reloading the page do not invalidate anything.

**Security architect** clearance requires a written supplier comparison for every technique used, at
least one control of each of the five purposes, all twelve incidents fully addressed, every declared
procedure supported and owned, equipment and procedures together within budget, all eight questions answered, and a written evaluation.

## Notifications

Every action that changes the design produces a toast: what happened, what it cost, what it means and
usually what to do next. Removing a control offers an undo. Deploying a control somewhere unusual warns
rather than blocks, and says where that control normally goes — the justification is the student's to
make. Toasts stack to three, pause on hover and focus, repeat messages collapse into a count, and the
whole region is a single polite live region for screen readers.

## Budget

The default £14,000 is a classroom constraint, not a recommended real-world budget; it is adjustable
in *Mission and lesson guide*. Several designs can address the checks. Use local supplier evidence and include installation assumptions; lower the budget to force trade-offs or raise it for whole-system quotes. Price one placement as one unit or a quoted system for the selected
zone. Ask students to identify estimates, VAT and installation assumptions. Keep evacuation routes
usable — physical security never overrides fire safety.

## Saving

Completed changes, written answers and incident notes autosave when browser storage is available. Unsubmitted product forms are not saved. Use **Save file** before switching devices; **Open file** restores a JSON checkpoint. Version 2 research, comparisons, placements, procedures and answers are retained. Old incident results become historical because the versioned check model changed. Version 1 saves are migrated where their product evidence is valid. Ambiguous legacy power protection, device locks and barriers need their capability confirmed in the product editor. Download a checkpoint if browser storage is unavailable or full.

Product images may use remote URLs or embedded PNG/JPG/WebP screenshots up to 500 KB. External
images can be blocked by suppliers; attaching a screenshot is more reliable.

## Teacher controls

In *Mission and lesson guide*: mission budget, research requirement, save/open a file, and
**Reset this device** to clear a shared machine between classes.

## Files

- `index.html` — application shell
- `style.css` — responsive and print styles
- `app.js` — curriculum, local state, product research, incident rules, exam practice

No build step. Fonts are optional Google Fonts with a system fallback. No student data is sent to an
application server. Opening supplier links and loading remote product images contacts those external
services.

## Version 3 changes

- Mission hub and a four-stage student journey, with a next objective and clearer navigation.
- Searchable research by name or purpose; all 18 techniques and both research modes retained.
- Connected shared corridor, main/service/maintenance entrances, visible room doors and emergency exit.
- Focused incident selection, optional predictions, persistent improvement notes and previous-test comparison.
- Empty-design baseline testing. Each run evaluates an immutable design snapshot; changing another tab during the animation cannot change that run.
- Explicit product capabilities distinguish UPS from surge protection, physical anchoring from marking, and rated vehicle barriers from fencing.
- Primary cooling does not earn points during its own failure. Biometric entry and local CCTV alternatives receive appropriate credit. Response needs local detection.
- Procedure ownership is checked consistently in the model and clearance. Evacuation works independently of suppression purchasing.
- Budget-checked undo, insecure-context-compatible IDs, keyboard-accessible floorplan and reduced-motion styling.
- Incident learning journal included in the printable report. Practice marks and XP are classroom feedback, not qualification grades.

## Maintainer checks

The app is still plain HTML/CSS/JavaScript with no production dependencies. Open the root `index.html` from the GitHub copy, or `dist/index.html` from the Sites checkout. Optional Vite preview: `npm install`, then `npm run dev`. Logic regression tests: `npm test` (Node 18+); no browser installation required.

The tests cover all 12 baseline incidents, control capability distinctions, local detection, procedure ownership, versioned results, immutable snapshots, save migration, view rendering and room connectivity. Product evidence and real installation suitability remain teacher-reviewed.
