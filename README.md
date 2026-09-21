# Secure the Office

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
2. **Deploy** products onto the office floorplan with a written justification for the zone and the supplier.
3. **Declare procedures** — visitor escorting, alarm response, key control, backups, disposal and so on.
   Procedures are charged to the same budget at an indicative annual cost, must be supported by equipment
   already in the design, and need a named owner.
4. **Test** against twelve incidents and use the debriefs to revise the design.
5. **Answer** eight exam-practice questions using the unit's command words, with indicative content to
   self-assess against.
6. **Evaluate** and print or save the mission report as a PDF.

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

Ticking all seven costs £2,740 of the £10,000 budget, so procedures compete with equipment for the same
money — which is the trade-off exam question 8 asks students to evaluate.

Each procedure also depends on equipment. Alarm response needs CCTV or intruder detection somewhere in the
design; fire response needs suppression; key control needs locks or an entry system; temperature changeover
needs cooling. A procedure with nothing behind it is charged for, flagged on the card and in the report, and
does **not** count when an incident is evaluated. Backup rotation and secure disposal have no equipment
dependency.

Every declared procedure needs a written owner — who does it, and how you would know it is actually
happening. That statement is required for clearance and appears on the printed report.

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

15 XP per complete product record; 25 per two-supplier comparison with a written choice; 15 per
deployment; 40 per incident fully addressed by the current design; 10 per exam question answered;
10 per supported procedure with a named owner.
Repeated runs of an unchanged design do not stack XP. Research, deployments, procedures and budget
changes invalidate old incident results.

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

The default £10,000 is a classroom constraint, not a recommended real-world budget; it is adjustable
in *Mission and lesson guide*. Price one placement as one unit or a quoted system for the selected
zone. Ask students to identify estimates, VAT and installation assumptions. Keep evacuation routes
usable — physical security never overrides fire safety.

## Saving

Progress is stored in the current browser only. **Save file** downloads a JSON checkpoint and
**Open file** resumes it on another PC. Save files from the previous version are migrated
automatically: products, placements, procedures and the evaluation carry over, and the old
compensating-cooling task is renamed. Incident results are cleared on migration because the
scenario checks changed. Browser storage has a quota — download a save file when prompted, and
always save before changing computer.

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
