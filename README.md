# Secure the Office

A browser-based physical-security lesson game. No installation, student account, backend or API key is needed.

## Run

Open `index.html` in a modern browser, or publish the repository root with GitHub Pages (Settings → Pages → Deploy from a branch → main → / root). All asset paths are relative, so the site works under `/physical/` or another subdirectory.

## Student journey

1. Research two products from different suppliers for each of 13 techniques (26 records), including name, image, description, supplier link, price and price basis/date.
2. Place chosen products on the office floorplan, giving a location and supplier-choice justification.
3. Include operational procedures such as visitor checks and alarm response.
4. Run nine incidents and use the feedback to improve the design.
5. Evaluate the design and print/save the mission report as PDF.

Progress is saved only to the current browser. Use **Save file** to download a JSON checkpoint and **Open file** to resume on another PC. Product images may use remote URLs or embedded PNG/JPG/WebP screenshots (maximum 500 KB each). External images can be blocked by suppliers; attaching a screenshot is more reliable. Browser storage has a quota: download a save file when prompted, and always save before changing PCs.

## Lesson coverage

- Preventative: specialist anti-picking locks, barriers, gates, cages, flood defence, primary temperature control.
- Detective: CCTV and motion sensors.
- Corrective: fire suppression and gas suppression.
- Directive: signage and mandatory employee/visitor ID display.
- Compensating: alternative temperature control, with an explanation of the primary control it replaces.

The original three lesson video titles are included as YouTube search links in the briefing.

## Scoring

20 XP per complete product record; 20 per two-supplier comparison; 15 per deployment up to 13; 60 per fully addressed incident on the current design. Repeated runs do not stack XP. Research, deployments, procedures and budget changes invalidate old incident results. Architect clearance requires all 26 records, all 13 supplier pairs, nine complete incident checks, a design within budget and a written evaluation of at least 40 characters. Written quality and source authenticity require teacher review.

## Simulation scope

Nine deterministic scenarios cover tailgating, vehicle access, server equipment, records, deliveries, flooding, office fire, server-room fire and cooling failure. Outcomes check control types, named zones and declared procedures. They are teaching feedback, not engineering predictions. Camera coverage, lock ratings, gas-system suitability, flood heights, price accuracy and product quality are not automatically verified. Controls do not become effective simply because a student has described them well; teacher discussion and evidence evaluation remain central.

The default £10,000 budget is adjustable in Mission & lesson guide. Price one placement as one unit or a quoted system for the selected zone. Clearly identify estimates, VAT and installation assumptions. Keep evacuation routes usable.

## Files

- `index.html`: application shell
- `style.css`: responsive and print styles
- `app.js`: curriculum, local state, product research and incident rules

The application runs without a build step. Fonts are optional Google Fonts; system fonts provide a fallback. No student data is sent to an application server. Opening supplier/search links and loading remote product images contact those external services.
