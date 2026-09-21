'use strict';
/* Secure the Office — physical security lab
   Mapped to Pearson Level 3 AAQ BTEC National in IT,
   Unit 2: Cyber Security and Incident Management.
   Content areas referenced: A1.1.2, A1.1.3, A1.1.4, A1.2.3, A1.2.4, A4, C1. */

/* ---------------------------------------------------------------- curriculum */

const SPEC = {
  'A1.1.2': 'A1.1.2 Accidental or deliberate damage',
  'A1.1.3': 'A1.1.3 Weak security measures and unsafe practices',
  'A1.1.4': 'A1.1.4 Accidental loss or disclosure of data',
  'A1.2.3': 'A1.2.3 Sabotage',
  'A1.2.4': 'A1.2.4 Social engineering',
  'A4': 'A4 Software and hardware security measures',
  'C1': 'C1 Internal policies'
};

const GROUPS = [
  ['Preventative', 'Stops an incident happening in the first place.'],
  ['Detective', 'Spots unauthorised activity and raises an alert.'],
  ['Corrective', 'Limits the damage once something has happened.'],
  ['Directive', 'Tells people what they must do.'],
  ['Compensating', 'Stands in when the primary control is unavailable or inadequate.']
];

/* group: index into GROUPS. zones: where this control is normally sited. */
const TYPES = [
  { id: 'locks', group: 0, spec: ['A4'], name: 'Door locks', blurb: 'Anti-pick or restricted-key locks on doors to protected rooms.', search: 'anti pick high security door lock UK', zones: ['server', 'records', 'delivery', 'plant'] },
  { id: 'access', group: 0, spec: ['A4'], name: 'Card or fob entry', blurb: 'Electronic access control that can be logged and revoked.', search: 'proximity card access control door entry system UK', zones: ['reception', 'server', 'records', 'delivery'] },
  { id: 'biometric', group: 0, spec: ['A4'], name: 'Biometric reader', blurb: 'Fingerprint or iris reader for the highest-risk doors.', search: 'fingerprint door access control reader UK', zones: ['server', 'records'] },
  { id: 'barriers', group: 0, spec: ['A4', 'A1.2.3'], name: 'Barriers and bollards', blurb: 'Fencing or bollards that keep vehicles off the site.', search: 'security bollards perimeter fencing UK', zones: ['perimeter'] },
  { id: 'gates', group: 0, spec: ['A4'], name: 'Controlled gate', blurb: 'A gate that controls vehicle and pedestrian entry.', search: 'automatic security gate commercial UK', zones: ['perimeter'] },
  { id: 'cages', group: 0, spec: ['A4'], name: 'Cabinet or cage', blurb: 'A locked rack or cage around the equipment itself.', search: 'lockable server rack cabinet UK', zones: ['server'] },
  { id: 'devicelock', group: 0, spec: ['A4'], name: 'Device locks', blurb: 'Cable locks, port blockers and asset marking for open areas.', search: 'laptop kensington cable lock asset tag UK', zones: ['office', 'reception', 'records'] },
  { id: 'flood', group: 0, spec: ['A1.1.2'], name: 'Flood defence', blurb: 'Keeps water away from equipment on the ground floor.', search: 'flood door barrier commercial UK', zones: ['server', 'delivery', 'plant'] },
  { id: 'cooling', group: 0, spec: ['A1.1.2'], name: 'Temperature control', blurb: 'Primary cooling that stops equipment overheating.', search: 'server room air conditioning UK', zones: ['server'] },
  { id: 'power', group: 0, spec: ['A1.1.2'], name: 'Power protection', blurb: 'UPS or surge protection so a power fault does not destroy data.', search: 'rack mount UPS uninterruptible power supply UK', zones: ['server', 'plant'] },
  { id: 'cctv', group: 1, spec: ['A4'], name: 'CCTV', blurb: 'Monitors activity and records evidence for later.', search: 'commercial CCTV camera system UK', zones: ['perimeter', 'reception', 'office', 'server', 'records', 'delivery', 'plant'] },
  { id: 'motion', group: 1, spec: ['A4'], name: 'Intruder detection', blurb: 'Motion sensors or door contacts that trigger an alarm.', search: 'commercial intruder alarm motion sensor UK', zones: ['server', 'records', 'delivery', 'office'] },
  { id: 'fire', group: 2, spec: ['A1.1.2'], name: 'Fire suppression', blurb: 'Extinguishers or sprinklers suited to the hazard in that room.', search: 'office fire extinguisher electrical rated UK', zones: ['office', 'reception', 'records', 'delivery', 'plant'] },
  { id: 'gas', group: 2, spec: ['A1.1.2'], name: 'Gas suppression', blurb: 'Inert or chemical suppression for an enclosed equipment room.', search: 'server room inert gas fire suppression UK', zones: ['server'] },
  { id: 'mediasafe', group: 2, spec: ['A4', 'A1.1.4'], name: 'Media safe', blurb: 'Fire-rated safe or cabinet for backup media and paper records.', search: 'fire rated data media safe UK', zones: ['records', 'server'] },
  { id: 'signs', group: 3, spec: ['C1'], name: 'Security signage', blurb: 'Makes the rules visible at the point people have to follow them.', search: 'restricted access security sign UK', zones: ['perimeter', 'reception', 'delivery', 'server'] },
  { id: 'badges', group: 3, spec: ['C1', 'A1.2.4'], name: 'ID badges', blurb: 'Staff and visitor identification that must be displayed.', search: 'employee visitor ID badge holder lanyard UK', zones: ['reception'] },
  { id: 'backupcool', group: 4, spec: ['A1.1.2'], name: 'Standby cooling', blurb: 'An alternative when the primary cooling is unavailable.', search: 'portable server room air conditioner UK', zones: ['server'] }
];

const ZONES = [
  ['perimeter', 'Perimeter and car park', 30, 40, 680, 65, 'Vehicle and pedestrian access from the road.', 'ROAD ACCESS + SITE BOUNDARY'],
  ['reception', 'Reception', 55, 145, 180, 130, 'Public entrance and visitor check-in.', 'PUBLIC TO STAFF ACCESS'],
  ['office', 'Staff workspace', 255, 145, 235, 130, 'Open-plan desks, laptops and staff equipment.', 'OPEN PLAN OFFICE'],
  ['server', 'Server room', 510, 145, 175, 130, 'Critical systems and sensitive equipment.', 'RESTRICTED / CRITICAL ASSETS'],
  ['records', 'Records store', 55, 305, 180, 135, 'Confidential paper files and backup media.', 'CONFIDENTIAL STORAGE'],
  ['delivery', 'Delivery entrance', 255, 305, 235, 135, 'Contractors and deliveries enter here.', 'SERVICE ACCESS'],
  ['plant', 'Plant and services', 510, 305, 175, 135, 'Cooling plant, power and environmental risks.', 'BUILDING SERVICES']
];

/* Procedures cost money and depend on equipment. `needs` is an any-of list of
   control ids: declare a procedure with nothing to support it and it does not count. */
const PROCEDURES = [
  { id: 'visitor', name: 'Visitor sign-in and escorting', cost: 420, spec: ['A1.1.3', 'C1'],
    desc: 'Visitors are signed in, badged and escorted; staff challenge anyone without a badge.',
    needs: ['badges'], needsText: 'Nobody can be challenged for not showing a badge if you have not issued any.' },
  { id: 'response', name: 'Alarm and CCTV response', cost: 540, spec: ['C1'],
    desc: 'A named person investigates alerts and knows who to call out of hours.',
    needs: ['cctv', 'motion'], needsText: 'There is nothing to respond to until you deploy CCTV or intruder detection.' },
  { id: 'fireplan', name: 'Fire response and evacuation', cost: 260, spec: ['A1.1.2'],
    desc: 'Staff raise the alarm and evacuate; equipment is used only if trained and safe.',
    needs: ['fire', 'gas'], needsText: 'A response plan needs suppression equipment for trained staff to use.' },
  { id: 'coolplan', name: 'Temperature monitoring and changeover', cost: 180, spec: ['A1.1.2'],
    desc: 'Temperature is monitored and staff switch to standby cooling on alert.',
    needs: ['cooling', 'backupcool'], needsText: 'There is nothing to monitor or change over to until cooling is installed.' },
  { id: 'keys', name: 'Key and access-card control', cost: 220, spec: ['A1.1.3', 'C1'],
    desc: 'Keys and cards are issued, logged and returned; leavers are revoked the same day.',
    needs: ['access', 'locks', 'biometric'], needsText: 'There are no keys or cards to control until you fit locks or an entry system.' },
  { id: 'backups', name: 'Backup rotation and offsite storage', cost: 780, spec: ['A4', 'C1'],
    desc: 'Backups are taken, moved offsite and restore-tested, not just written.',
    needs: [], needsText: '' },
  { id: 'disposal', name: 'Secure disposal', cost: 340, spec: ['A1.1.4', 'C1'],
    desc: 'Old drives and paper are shredded or destroyed to a certificate, not binned.',
    needs: [], needsText: '' }
];

/* ------------------------------------------------------------------ examples
   A reference shelf, not a shop. These are generic product CATEGORIES with the
   typical UK price range for one unit, so a student knows roughly what they are
   looking for and whether the page they have found is sensibly priced. Nothing
   here can be saved as evidence: the record still has to be a real supplier page
   the student found, priced and dated themselves. Ranges are classroom estimates,
   exclude installation unless stated, and go out of date — check them each year. */
const EXAMPLES = {
  locks: { low: 25, high: 90, unit: 'per door', check: 'Quote the standard (TS007 3-star, SS312 Diamond, BS3621), not just "high security".', items: [
    ['Anti-snap euro cylinder', 'Swaps into an existing door in minutes. Cheapest real upgrade there is.'],
    ['Restricted-key mortice deadlock', 'Keys can only be cut against a registered code, so copies are controlled.']] },
  access: { low: 180, high: 900, unit: 'per door', check: 'Say whether the price is one standalone door kit or a per-door share of a networked system, and whether the maglock and power supply are included.', items: [
    ['Standalone proximity door kit', 'Reader, controller, lock release and power supply for one door. No central log.'],
    ['Networked access control per door', 'Logs who opened what and when, and revokes a card centrally. The logging is the point.']] },
  biometric: { low: 120, high: 500, unit: 'per door', check: 'Note the false-acceptance rate and what happens when the reader fails or a finger is wet.', items: [
    ['Fingerprint reader for one door', 'Ties entry to a person rather than to a card that can be lent or lost.'],
    ['Reader with card fallback', 'Two factors at the door; the fallback is also the weak point to discuss.']] },
  barriers: { low: 90, high: 400, unit: 'each, before groundworks', check: 'Bollard prices almost never include the digging and concrete. Say so.', items: [
    ['Fixed steel bollard, root-fixed', 'Stops a vehicle reaching the wall. Cheap per unit, you need several.'],
    ['Removable or telescopic bollard', 'Keeps a fire route or delivery bay usable. Dearer, and depends on someone locking it.']] },
  gates: { low: 600, high: 5000, unit: 'per gate', check: 'Manual or automated changes the price by thousands. Name which, and whether install is in the figure.', items: [
    ['Manual swing or sliding gate', 'Controls the entrance at a price a small office can defend.'],
    ['Automated sliding gate with intercom', 'Controls entry without staff walking out, but needs power, safety edges and maintenance.']] },
  cages: { low: 250, high: 900, unit: 'each', check: 'Give the size (U height or cage dimensions) — a rack that does not fit the kit is not a control.', items: [
    ['Lockable server rack cabinet', 'A second layer around the equipment once someone is in the room.'],
    ['Welded mesh equipment cage', 'Encloses kit that cannot go in a cabinet, such as a rack that stays open.']] },
  devicelock: { low: 15, high: 80, unit: 'each or per pack', check: 'Per device or per pack? Twenty-four desks needs twenty-four locks.', items: [
    ['Cable lock for laptops', 'Stops the opportunist walk-past. Does not stop someone with cutters.'],
    ['Tamper-evident asset labels', 'Marks ownership and makes resale harder; helps recovery, not prevention.']] },
  flood: { low: 250, high: 1400, unit: 'per opening', check: 'Give the protected height in mm and say who is expected to deploy it, and when.', items: [
    ['Demountable flood barrier for a doorway', 'Cheap, but someone has to fit it before the water arrives.'],
    ['Automatic or permanent flood door', 'Works with nobody on site. Several times the price.']] },
  cooling: { low: 900, high: 2500, unit: 'per unit, install extra', check: 'Quote the cooling capacity in kW against the load in the room, not just the box price.', items: [
    ['Wall-mounted split air conditioner', 'Standard answer for a small comms room. Install is usually a separate quote.'],
    ['Dedicated close-control cooling unit', 'Built for equipment rather than people. Better, dearer, needs a plant space.']] },
  power: { low: 350, high: 1200, unit: 'per unit', check: 'Say the VA rating and the runtime you expect at your load — "a UPS" is not an answer.', items: [
    ['Rack-mount line-interactive UPS', 'Rides out a short cut and shuts the servers down cleanly.'],
    ['Online double-conversion UPS', 'Also cleans dirty mains. Dearer and less efficient.']] },
  cctv: { low: 60, high: 700, unit: 'per camera, or per kit', check: 'One camera or a four-camera kit with a recorder? Say which, and how long recordings are kept.', items: [
    ['IP dome or turret camera', 'Priced per camera; you need one per area you claim to cover.'],
    ['Four-camera NVR kit', 'Recorder and cameras together — usually the honest way to price a small site.']] },
  motion: { low: 20, high: 450, unit: 'per sensor, or per kit', check: 'A sensor is not an alarm. Say whether the price includes the panel and who the signal goes to.', items: [
    ['PIR sensor or door contact', 'Added to an existing panel. Pennies compared with the panel itself.'],
    ['Wireless intruder alarm kit', 'Panel, sensors and siren for a small site, self-monitored.']] },
  fire: { low: 40, high: 150, unit: 'each', check: 'Match the extinguisher class to the hazard — CO2 or clean agent near electrical equipment, not water.', items: [
    ['CO2 extinguisher', 'For electrical risks. Leaves no residue on equipment.'],
    ['Foam or water extinguisher', 'For paper and furniture. Wrong tool for a live electrical fire.']] },
  gas: { low: 250, high: 10000, unit: 'rack unit vs room system', check: 'A rack-sized aerosol unit and a room-flooding clean-agent system differ by a factor of twenty. Say which you are pricing.', items: [
    ['Self-actuating aerosol unit for a rack', 'Sits above the kit and discharges on heat. Affordable, protects the rack only.'],
    ['Room clean-agent suppression system', 'Protects the whole room. Needs design, sealing, alarms and signage.']] },
  mediasafe: { low: 300, high: 1200, unit: 'each', check: 'Data media need a lower internal temperature than paper — quote the media rating and the protection time.', items: [
    ['Fire-rated data media safe', 'Rated to keep tapes and drives below their survival temperature.'],
    ['Fire-resisting document cabinet', 'Paper-rated only; cheaper, and not enough for backup media.']] },
  signs: { low: 8, high: 30, unit: 'each', check: 'Cheap, so there is no excuse for an unsigned restricted door. Say where each sign goes.', items: [
    ['Rigid restricted-access sign', 'Puts the rule where the person has to decide.'],
    ['CCTV in operation sign', 'Also a legal expectation where cameras record the public.']] },
  badges: { low: 50, high: 900, unit: 'per pack, or per printer', check: 'Cards and lanyards are pounds; a printer that lets you issue and void them is hundreds. Say which you bought.', items: [
    ['Visitor badge book and holders', 'Enough for a 24-person office with visitors, for very little.'],
    ['ID card printer and blank cards', 'Lets you issue and reissue staff cards in-house.']] },
  backupcool: { low: 350, high: 900, unit: 'each', check: 'Say what it stands in for and how long it can hold the room — that is what makes it compensating.', items: [
    ['Portable air conditioner with ducting', 'Wheeled in when the primary unit fails. Needs somewhere to vent.'],
    ['Second fixed split unit on changeover', 'Better, and only compensating if it is normally off.']] }
};
const exRange = id => EXAMPLES[id] ? `${money0(EXAMPLES[id].low)}–${money0(EXAMPLES[id].high)} ${EXAMPLES[id].unit}` : '';
function examplesBlock(id) {
  const e = EXAMPLES[id];
  if (!e) return '';
  return `<details class="examples">
    <summary>Typical products and prices</summary>
    <p class="tiny">Classroom reference only — you still have to find a real supplier page, price it and date it.</p>
    ${e.items.map(([name, note]) => `<p class="ex-item"><b>${name}</b><span>${note}</span></p>`).join('')}
    <p class="ex-range"><b>Typical UK range:</b> ${exRange(id)}</p>
    <p class="tiny"><b>What to quote:</b> ${e.check}</p>
  </details>`;
}

/* checks are built at evaluation time; here: id, title, brief, zone, spec */
const SCENARIOS = [
  ['tailgate', 'The extra visitor', 'A visitor follows a member of staff through the door from reception without signing in.', 'reception', 'A1.2.4'],
  ['vehicle', 'After-hours arrival', 'An unauthorised vehicle drives onto the site boundary at night.', 'perimeter', 'A1.2.3'],
  ['server', 'The server-room target', 'An intruder reaches the door of the restricted equipment room.', 'server', 'A4'],
  ['records', 'Missing records', 'Movement is detected near the confidential files after closing.', 'records', 'A4'],
  ['delivery', 'The open delivery route', 'An unfamiliar contractor tries to walk in through the delivery entrance.', 'delivery', 'A1.1.3'],
  ['laptop', 'The empty desk', 'A laptop disappears from an open-plan desk during a busy lunchtime.', 'office', 'A1.1.3'],
  ['leaver', 'The card that still works', 'A member of staff who left last month still has a working entry card.', 'reception', 'A1.1.3'],
  ['flood', 'Rising water', 'Floodwater from the river reaches the ground-floor service entrances.', 'plant', 'A1.1.2'],
  ['fire', 'Smoke in the office', 'An electrical fault starts a small fire in the open-plan office.', 'office', 'A1.1.2'],
  ['gas', 'Smoke in the server room', 'Fire threatens critical equipment in the enclosed server room.', 'server', 'A1.1.2'],
  ['heat', 'Cooling failure', 'Primary server-room cooling stops working on a hot afternoon.', 'server', 'A1.1.2'],
  ['power', 'The power cut', 'A substation fault cuts mains power to the building during the working day.', 'plant', 'A1.1.2']
];

/* Exam-style practice. Command words match the Unit 2 external assessment. */
const QUESTIONS = [
  { id: 'q1', cmd: 'Identify', marks: 2, spec: 'A4', prompt: 'Identify two preventative physical security measures you have installed at the site perimeter.', indicative: ['One mark for each correctly named perimeter control, e.g. bollards, fencing, a controlled gate.', 'A detective control such as CCTV does not earn the mark here: it records, it does not prevent.'] },
  { id: 'q2', cmd: 'Describe', marks: 4, spec: 'A1.1.2', prompt: 'Describe two physical measures in your design that protect equipment from accidental or deliberate damage, and say what each one protects against.', indicative: ['One mark for naming each measure, one for linking it to a named hazard.', 'Accept flood barriers (water), suppression (fire), UPS (power loss or surge), cooling (overheating), media safe (loss of backups).', 'Damage here is not only malicious: fires, floods and power failures count.'] },
  { id: 'q3', cmd: 'Explain', marks: 4, spec: 'A4', prompt: 'Explain why fitting a high-security lock to the server-room door does not, on its own, protect the equipment inside.', indicative: ['A single control is a single point of failure: a lock can be bypassed, propped open or defeated with a stolen key or card.', 'It does nothing about anyone already inside the building, or about staff who hold legitimate access.', 'It gives no alert and no evidence, so a defeat goes unnoticed.', 'Layers such as a cage, detection, and a response procedure cover what the lock cannot. This is defence in depth.'] },
  { id: 'q4', cmd: 'Explain', marks: 4, spec: 'A4', prompt: 'Explain how CCTV helps an organisation both during and after a security incident.', indicative: ['During: it detects activity and lets a responder see what is happening before deciding how to act.', 'After: the recording is evidence for investigation, insurance, disciplinary action or the police.', 'Credit the limitation: CCTV is detective, not preventative. It does not stop entry, and it only helps if someone monitors or reviews it.'] },
  { id: 'q5', cmd: 'Explain', marks: 6, spec: 'A1.1.3', prompt: 'Explain why physical security measures depend on staff procedures. Use two procedures from your design as examples.', indicative: ['Equipment only works if people use it as intended, so human behaviour is part of the control, not separate from it.', 'Badges do not stop tailgating unless staff challenge people without one.', 'An alarm does nothing unless a named responder investigates it.', 'Access cards stay a risk until a leaver process revokes them.', 'Six marks needs two developed examples, each with the measure, the procedure and the consequence of the procedure failing.'] },
  { id: 'q6', cmd: 'Explain', marks: 4, spec: 'A1.1.2', prompt: 'Explain the difference between a compensating control and a second preventative control, using the cooling in your design as an example.', indicative: ['A compensating control substitutes for a primary control that is unavailable or inadequate; it addresses the same risk by another route.', 'A second preventative control adds another layer while the first is still working.', 'Standby cooling only compensates when primary cooling has failed; running both continuously would be redundancy, not compensation.'] },
  { id: 'q7', cmd: 'Evaluate', marks: 8, spec: 'A4', prompt: 'Evaluate your finished design against the budget. Explain what you prioritised, what you left out, and what risk remains.', indicative: ['A judgement is needed, not a list: which zones got the money and why those were the highest risk.', 'Reference the value of the assets in each zone, not just the cost of the kit.', 'Name at least one control that was cut and what that exposes.', 'Name a residual risk that money would not fix, e.g. staff behaviour, a shared door, an installation limit.', 'Top band: a supported judgement with trade-offs on both sides and a clear recommendation.'] },
  { id: 'q8', cmd: 'Evaluate', marks: 6, spec: 'C1', prompt: 'Evaluate whether an organisation gets better value from spending £2,000 on physical security equipment or on staff training and procedures.', indicative: ['Both sides needed. Equipment works without cooperation and produces evidence, but is fixed, costly and can be bypassed.', 'Training addresses social engineering and tailgating, which no lock prevents, but it decays and depends on culture.', 'The strongest answers reject the either/or and justify a split with reference to the specific risks in the scenario.', 'The student has made this exact trade-off in their own design — credit any reference to what they spent on equipment against what they spent on procedures.'] }
];

/* ---------------------------------------------------------------- state */

const STORE_KEY = 'secure-office-v2';
const LEGACY_KEY = 'secure-office-v1';

const fresh = () => ({
  version: 2,
  team: '',
  budget: 14000,
  researchRule: 'deployed',   // 'deployed' = compare suppliers for controls you use; 'all' = every technique
  products: {},               // typeId -> [slot0, slot1]
  compare: {},                // typeId -> written supplier comparison
  placements: [],
  procedures: {},
  procedureNotes: {},   // who owns each declared procedure
  runs: [],
  answers: {},                // questionId -> { text, mark }
  reflection: ''
});

let state = fresh();
let tab = 'plan';
let zone = 'reception';
let activeRun = null;
let running = false;
let editImage = '';
let lastRank = '';

/* ---------------------------------------------------------------- helpers */

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const money = n => new Intl.NumberFormat('en-GB', { style: 'currency', currency: 'GBP', maximumFractionDigits: 2 }).format(n || 0);
const money0 = n => new Intl.NumberFormat('en-GB', { style: 'currency', currency: 'GBP', maximumFractionDigits: 0 }).format(n || 0);
const type = id => TYPES.find(t => t.id === id);
const zname = id => ZONES.find(z => z[0] === id)?.[1] || id;
const zinfo = id => ZONES.find(z => z[0] === id);
const proc = id => PROCEDURES.find(p => p.id === id);
const weburl = s => { try { return ['http:', 'https:'].includes(new URL(s).protocol); } catch { return false; } };
const imgurl = s => weburl(s) || /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(s);
const specTag = codes => codes.map(c => `<span class="spec" title="${esc(SPEC[c] || c)}">${esc(c)}</span>`).join('');

function validProduct(p) {
  return !!p
    && ['name', 'supplier', 'description', 'url', 'image', 'priceNote'].every(k => typeof p[k] === 'string' && p[k].trim())
    && weburl(p.url) && imgurl(p.image)
    && Number.isFinite(p.price) && p.price >= 0;
}
function pairReady(id) {
  const a = state.products[id] || [];
  return validProduct(a[0]) && validProduct(a[1])
    && a[0].supplier.trim().toLowerCase() !== a[1].supplier.trim().toLowerCase();
}
function compareReady(id) {
  return pairReady(id) && (state.compare[id] || '').trim().length >= 40;
}
/* Which techniques must be researched, given the current rule. */
function requiredTypes() {
  if (state.researchRule === 'all') return TYPES.map(t => t.id);
  return [...new Set(state.placements.map(p => p.type))];
}
const has = (t, z) => state.placements.some(p => p.type === t && p.zone === z);
const hasAny = (t) => state.placements.some(p => p.type === t);

function equipSpent() {
  return state.placements.reduce((a, p) => a + (state.products[p.type]?.[p.slot]?.price || 0), 0);
}
function procSpent() {
  return PROCEDURES.reduce((a, p) => a + (state.procedures[p.id] ? p.cost : 0), 0);
}
function spent() { return equipSpent() + procSpent(); }

/* A procedure only counts if something in the design supports it. */
function supported(id) {
  const p = proc(id);
  return !p.needs.length || p.needs.some(hasAny);
}
function declared(id) { return !!state.procedures[id] && supported(id); }
function ownerNote(id) { return (state.procedureNotes[id] || '').trim(); }
function procComplete(id) { return declared(id) && ownerNote(id).length >= 25; }
/* Fingerprint of the DESIGN only: which control sits in which zone, at what price,
   plus the declared procedures and the budget. Deliberately NOT the whole products
   object — recording a second supplier, fixing a typo or reloading the page must not
   invalidate incident results. Sorted so key order can never change the hash. */
function signature() {
  const design = state.placements
    .map(p => `${p.type}|${p.zone}|${p.slot}|${state.products[p.type]?.[p.slot]?.price ?? 0}`)
    .sort();
  const text = JSON.stringify([design, PROCEDURES.map(x => !!state.procedures[x.id]), state.budget]);
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0).toString(16);
}
function latestRuns() {
  return SCENARIOS
    .map(s => [...state.runs].reverse().find(r => r.id === s[0] && r.signature === signature()))
    .filter(Boolean);
}
function staleRuns() {
  return state.runs.length > 0 && latestRuns().length < state.runs.length && latestRuns().length < SCENARIOS.length;
}
function counts() {
  const req = requiredTypes();
  return {
    /* records that count towards XP: up to two for each technique actually required */
    products: req.reduce((n, t) => n + Math.min(2, (state.products[t] || []).filter(validProduct).length), 0),
    /* every complete record on file, deployed or not — display only */
    recorded: TYPES.reduce((n, t) => n + (state.products[t.id] || []).filter(validProduct).length, 0),
    pairs: req.filter(pairReady).length,
    compares: req.filter(compareReady).length,
    required: req.length,
    wins: latestRuns().filter(r => r.score === 100).length,
    answered: QUESTIONS.filter(q => (state.answers[q.id]?.text || '').trim().length >= 30).length,
    procsOn: PROCEDURES.filter(p => state.procedures[p.id]).length,
    procsDone: PROCEDURES.filter(p => procComplete(p.id)).length,
    procsUnsupported: PROCEDURES.filter(p => state.procedures[p.id] && !supported(p.id)).length,
    purposes: GROUPS.map((g, i) => state.placements.some(p => type(p.type)?.group === i))
  };
}
/* A design that fully addresses all twelve incidents needs 17 of the 18 techniques
   and 27 placements. The meter measures distance to THAT, so a student cannot reach
   a high rank by filling in product forms and building nothing. */
const CLEARANCE_TYPES = 17;
const CLEARANCE_PLACEMENTS = 27;
function maxXp() {
  const req = state.researchRule === 'all'
    ? TYPES.length
    : Math.max(CLEARANCE_TYPES, requiredTypes().length);
  return req * 30 + req * 25 + CLEARANCE_PLACEMENTS * 15
    + SCENARIOS.length * 60 + QUESTIONS.length * 10 + PROCEDURES.length * 10;
}
function xpNow() {
  const c = counts();
  return c.products * 15 + c.compares * 25 + Math.min(state.placements.length, CLEARANCE_PLACEMENTS) * 15
    + c.wins * 60 + c.answered * 10 + c.procsDone * 10;
}
function clearance() {
  const c = counts();
  return c.required > 0
    && c.compares === c.required
    && c.purposes.every(Boolean)
    && c.wins === SCENARIOS.length
    && c.procsOn === c.procsDone
    && spent() <= state.budget
    && state.reflection.trim().length >= 120
    && c.answered === QUESTIONS.length;
}

/* ---------------------------------------------------------------- persistence */

function migrate(s) {
  if (!s || typeof s !== 'object') throw Error('That is not a Secure the Office save file.');
  if (s.version === 2) return s;
  if (s.version === 1) {
    const out = { ...fresh(), version: 2, team: s.team, budget: s.budget, reflection: s.reflection, researchRule: 'all' };
    const renamed = { backup: 'backupcool' };
    for (const [k, v] of Object.entries(s.products || {})) {
      const id = renamed[k] || k;
      if (type(id)) out.products[id] = v;
    }
    out.compare = {};
    for (const [k, v] of Object.entries(s.selectionReasons || {})) {
      const id = renamed[k] || k;
      if (type(id) && v) out.compare[id] = v;
    }
    out.placements = (s.placements || []).map(p => ({ ...p, type: renamed[p.type] || p.type }));
    out.procedures = s.procedures || {};
    out.runs = [];   // scenario checks changed, so old results are not comparable
    return out;
  }
  throw Error('That save file was made by a different version.');
}

function validateState(raw) {
  const s = migrate(raw);
  if (!s.products || typeof s.products !== 'object' || !Array.isArray(s.placements) || !s.procedures) throw Error('That file is missing its mission data.');
  const n = fresh();
  n.team = String(s.team || '').slice(0, 100);
  n.budget = Number(s.budget);
  if (!Number.isFinite(n.budget) || n.budget < 0 || n.budget > 1000000) throw Error('That file has an invalid budget.');
  n.researchRule = s.researchRule === 'all' ? 'all' : 'deployed';
  for (const t of TYPES) {
    const ps = s.products[t.id];
    if (ps) {
      if (!Array.isArray(ps) || ps.length > 2 || ps.some(p => p && !validProduct(p))) throw Error('That file has invalid product evidence.');
      n.products[t.id] = ps;
    }
    n.compare[t.id] = String(s.compare?.[t.id] || '').slice(0, 5000);
  }
  n.placements = (s.placements || []).filter(p =>
    p && type(p.type) && ZONES.some(z => z[0] === p.zone) && [0, 1].includes(p.slot)
    && validProduct(n.products[p.type]?.[p.slot])
    && typeof p.reason === 'string' && p.reason.trim()
    && typeof p.id === 'string' && /^[a-zA-Z0-9-]+$/.test(p.id)
  ).slice(0, 150);
  for (const p of PROCEDURES) {
    n.procedures[p.id] = s.procedures[p.id] === true;
    n.procedureNotes[p.id] = String(s.procedureNotes?.[p.id] || '').slice(0, 2000);
  }
  n.runs = (s.runs || []).filter(r =>
    r && SCENARIOS.some(x => x[0] === r.id) && Array.isArray(r.checks)
    && r.checks.every(c => typeof c.ok === 'boolean' && typeof c.text === 'string')
    && Number.isFinite(r.score) && r.score >= 0 && r.score <= 100 && typeof r.signature === 'string'
  ).slice(-120);
  for (const q of QUESTIONS) {
    const a = s.answers?.[q.id];
    if (a) n.answers[q.id] = { text: String(a.text || '').slice(0, 6000), mark: Number(a.mark) >= 0 ? Math.min(Number(a.mark), q.marks) : null };
  }
  n.reflection = String(s.reflection || '').slice(0, 12000);
  return n;
}

try {
  const raw = localStorage.getItem(STORE_KEY) || localStorage.getItem(LEGACY_KEY);
  if (raw) state = validateState(JSON.parse(raw));
} catch (e) { /* start fresh */ }

function persist() {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(state));
    setSaved('Autosaved ' + new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }));
  } catch (e) {
    setSaved('Storage full — save a file');
    toast('Device storage is full', { type: 'error', detail: 'Nothing new can be saved here. Use Save file to keep your work, then carry on.', duration: 9000 });
  }
  updateStats();
}
function setSaved(text) { const el = $('#saved'); if (el) el.textContent = text; }

/* ---------------------------------------------------------------- toasts */

const ICONS = { ok: '✓', info: 'i', warn: '!', error: '!', xp: '★' };
let toastSeq = 0;
const liveToasts = [];

/**
 * toast(title, { type, detail, duration, action: {label, run}, key })
 * type: ok | info | warn | error | xp
 */
function toast(title, opts = {}) {
  const host = $('#toasts');
  if (!host) return;
  const type = opts.type || 'info';
  const key = opts.key || (type + '|' + title);

  // repeat of the same message: bump the count instead of stacking duplicates
  const twin = liveToasts.find(t => t.key === key);
  if (twin) {
    twin.count++;
    const badge = twin.el.querySelector('.toast-count');
    badge.textContent = '×' + twin.count;
    badge.hidden = false;
    restartTimer(twin);
    return;
  }

  while (liveToasts.length >= 3) dismissToast(liveToasts[0]);

  const duration = opts.duration || (type === 'error' ? 8000 : opts.action ? 7000 : 4800);
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.innerHTML = `
    <span class="toast-icon" aria-hidden="true">${ICONS[type] || 'i'}</span>
    <div class="toast-body">
      <b>${esc(title)}<span class="toast-count" hidden></span></b>
      ${opts.detail ? `<p>${esc(opts.detail)}</p>` : ''}
      ${opts.action ? `<button class="toast-action" type="button">${esc(opts.action.label)}</button>` : ''}
    </div>
    <button class="toast-close" type="button" aria-label="Dismiss notification">✕</button>
    <i class="toast-timer"></i>`;

  const item = { id: ++toastSeq, key, el, count: 1, timer: null, duration };
  el.querySelector('.toast-close').onclick = () => dismissToast(item);
  const actionBtn = el.querySelector('.toast-action');
  if (actionBtn) actionBtn.onclick = () => { dismissToast(item); opts.action.run(); };
  el.onmouseenter = () => pauseTimer(item);
  el.onmouseleave = () => restartTimer(item);
  el.addEventListener('focusin', () => pauseTimer(item));
  el.addEventListener('focusout', () => restartTimer(item));

  host.appendChild(el);
  liveToasts.push(item);
  requestAnimationFrame(() => el.classList.add('in'));
  restartTimer(item);
}

function restartTimer(item) {
  clearTimeout(item.timer);
  const bar = item.el.querySelector('.toast-timer');
  bar.style.animation = 'none';
  void bar.offsetWidth;
  bar.style.animation = `toastbar ${item.duration}ms linear forwards`;
  item.timer = setTimeout(() => dismissToast(item), item.duration);
}
function pauseTimer(item) {
  clearTimeout(item.timer);
  item.el.querySelector('.toast-timer').style.animationPlayState = 'paused';
}
function dismissToast(item) {
  clearTimeout(item.timer);
  const i = liveToasts.indexOf(item);
  if (i > -1) liveToasts.splice(i, 1);
  item.el.classList.remove('in');
  item.el.classList.add('out');
  setTimeout(() => item.el.remove(), 220);
}

/* ---------------------------------------------------------------- stats bar */

function rankName() {
  if (clearance()) return 'Security architect';
  const pct = xpNow() / maxXp();
  if (pct >= 0.7) return 'Defence designer';
  if (pct >= 0.35) return 'Security analyst';
  return 'Security trainee';
}

function updateStats() {
  const c = counts(), xp = xpNow(), over = spent() > state.budget;
  $('#rank').textContent = rankName();
  $('#xp').textContent = c.required
    ? `${xp} XP · ${c.compares}/${c.required} supplier comparisons`
    : `${xp} XP · nothing deployed yet`;
  $('#progress').style.width = (clearance() ? 100 : Math.min(100, xp / maxXp() * 100)) + '%';
  $('#budget').textContent = over ? money(spent() - state.budget) + ' over' : money(state.budget - spent()) + ' left';
  $('#budget').classList.toggle('over', over);

  if (lastRank && rankName() !== lastRank) {
    toast(`Clearance raised: ${rankName()}`, {
      type: 'xp',
      detail: clearance()
        ? 'Every requirement is met. Print your report and hand it in.'
        : `${xp} XP. Keep going: ${nextGoal()}`
    });
  }
  lastRank = rankName();
}

function nextGoal() {
  const c = counts();
  if (!state.placements.length) return 'research a product and deploy it to a zone.';
  if (c.compares < c.required) return `write the supplier comparison for ${c.required - c.compares} more technique(s).`;
  if (!c.purposes.every(Boolean)) return `deploy a ${GROUPS[c.purposes.findIndex(p => !p)][0].toLowerCase()} control.`;
  if (c.procsUnsupported) return `${c.procsUnsupported} procedure(s) have no equipment behind them.`;
  if (c.procsOn > c.procsDone) return `say who owns ${c.procsOn - c.procsDone} of your procedures.`;
  if (c.wins < SCENARIOS.length) return `close the gaps in ${SCENARIOS.length - c.wins} more incident(s).`;
  if (spent() > state.budget) return 'bring the design back within budget.';
  if (c.answered < QUESTIONS.length) return `answer ${QUESTIONS.length - c.answered} more exam question(s).`;
  if (state.reflection.trim().length < 120) return 'write your final evaluation.';
  return 'review your report.';
}

/* ---------------------------------------------------------------- render */

const TABS = [
  ['plan', 'Defence planner'],
  ['research', 'Research lab'],
  ['simulate', 'Incident simulator'],
  ['exam', 'Exam practice'],
  ['report', 'Mission report'],
  ['brief', 'Mission and lesson guide']
];

function setTab(t, announce) {
  tab = t;
  render();
  document.querySelector('main')?.scrollTo?.({ top: 0 });
  if (announce) toast(announce.title, announce.opts);
}

function head(title, desc, extra = '') {
  return `<div class="pagehead"><div><h1>${title}</h1><p>${desc}</p></div>${extra}</div>`;
}

function render() {
  $('#nav').innerHTML = TABS.map(t =>
    `<button class="${tab === t[0] ? 'active' : ''}" ${tab === t[0] ? 'aria-current="page"' : ''} onclick="setTab('${t[0]}')">${t[1]}</button>`
  ).join('');
  const views = { plan: planView, research: researchView, simulate: simView, exam: examView, report: reportView, brief: briefView };
  $('#app').innerHTML = (views[tab] || planView)();
  updateStats();
}

/* ---------------------------------------------------------------- floorplan */

/* Doorways: [zone, centre x, wall y, swing (1 = opens downward), room is above the wall] */
const DOORW = 30;
const DOORS = [
  ['reception', 180, 145,  1, false],   // main entrance, through the porch
  ['reception', 100, 275,  1, true],
  ['office',    300, 275,  1, true],
  ['server',    545, 275,  1, true],
  ['records',   190, 305, -1, false],
  ['delivery',  440, 305, -1, false],
  ['plant',     650, 305, -1, false],
  ['delivery',  365, 440, -1, true]     // service door
];

function doorways() {
  return DOORS.map(([id, cx, wy, d, roomAbove]) => {
    const room = zone === id ? '#e8f5d1' : '#ffffff', corridor = '#d7e1e5';
    const above = roomAbove ? room : corridor, below = roomAbove ? corridor : room;
    const hx = cx - DOORW / 2;
    return `<g class="door" aria-hidden="true">
      <rect x="${hx}" y="${wy - 2.5}" width="${DOORW}" height="2.5" fill="${above}"/>
      <rect x="${hx}" y="${wy}" width="${DOORW}" height="2.5" fill="${below}"/>
      <path d="M${cx + DOORW / 2} ${wy}A${DOORW} ${DOORW} 0 0 ${d > 0 ? 1 : 0} ${hx} ${wy + DOORW * d}" fill="none" stroke="#a7b8c1" stroke-width="1.5"/>
      <line x1="${hx}" y1="${wy}" x2="${hx}" y2="${wy + DOORW * d}" stroke="#71838e" stroke-width="2.5"/>
    </g>`;
  }).join('');
}

function mapView(attack = '') {
  /* The outer shell is a gapped path so the two external doors break the wall. */
  const shell = 'M40 130H163M197 130H700M700 130V455M700 455H382M348 455H40M40 455V130';
  return `<svg class="map" viewBox="0 0 740 500" role="group" aria-label="Office floorplan. Seven zones off a central corridor, with a main entrance into reception and a service door into the delivery entrance. Choose a zone on the plan, or use the buttons below it.">
    <defs><pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M20 0H0V20" fill="none" stroke="#dce6e8" stroke-width=".5"/></pattern></defs>
    <rect width="740" height="500" fill="url(#grid)"/>
    <text x="30" y="24">SITE PLAN / GROUND FLOOR</text><text x="668" y="24">N &#8593;</text>
    <rect x="40" y="130" width="660" height="325" fill="#d7e1e5"/>
    <path d="${shell}" fill="none" stroke="#5b6f7d" stroke-width="4"/>
    ${ZONES.map(z => {
      const n = state.placements.filter(p => p.zone === z[0]).length;
      return `<g role="button" tabindex="0" aria-pressed="${zone === z[0]}"
        aria-label="${z[1]}. ${n} control${n === 1 ? '' : 's'} deployed. ${zinfo(z[0])[6]}"
        onclick="selectZone('${z[0]}')"
        onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();selectZone('${z[0]}')}">
        <title>${z[1]} — ${n} control${n === 1 ? '' : 's'} deployed</title>
        <rect class="zone ${zone === z[0] ? 'selected' : ''}" x="${z[2]}" y="${z[3]}" width="${z[4]}" height="${z[5]}" rx="3"/>
        <text class="roomname" x="${z[2] + 12}" y="${z[3] + 25}">${z[1]}</text>
        <text x="${z[2] + 12}" y="${z[3] + 45}">${z[7]}</text>
        ${n ? `<text class="zone-count" x="${z[2] + 12}" y="${z[3] + z[5] - 12}">&#9679; ${n} control${n === 1 ? '' : 's'}</text>` : ''}
      </g>`;
    }).join('')}
    ${doorways()}
    ${ZONES.filter(z => attack === z[0]).map(z =>
      `<rect class="attack-ring" x="${z[2] + 5}" y="${z[3] + 5}" width="${z[4] - 10}" height="${z[5] - 10}" rx="4"/>`).join('')}
    <text x="60" y="293">INTERNAL CORRIDOR</text>
    <text x="205" y="124" class="doorlabel">MAIN ENTRANCE</text>
    <text x="392" y="472" class="doorlabel">SERVICE DOOR</text>
    <text x="30" y="484">SCHEMATIC &#8226; NOT TO SCALE</text>
    <text x="500" y="484">RIVER / FLOOD EXPOSURE &#8595;</text>
  </svg>`;
}

function selectZone(id) {
  if (zone === id) return;
  zone = id;
  if (tab === 'plan') render();
}

/* ---------------------------------------------------------------- planner */

function planView() {
  const stock = TYPES.flatMap(t => (state.products[t.id] || [])
    .map((p, k) => validProduct(p) ? { t, p, k } : null).filter(Boolean));
  const c = counts();
  const purposeStrip = GROUPS.map((g, i) =>
    `<span class="purpose ${c.purposes[i] ? 'done' : ''}">${c.purposes[i] ? '✓' : '○'} ${g[0]}</span>`).join('');

  return head('Build a layered defence.',
    'Pick a zone, choose a product you have researched, and justify why that control belongs there.',
    `<button onclick="setTab('research')">Research products</button>`) +
    (staleRuns() ? `<div class="notice warning">Your design has changed since you last tested it. Run the incidents again to see the effect.</div>` : '') +
    `<div class="workspace">
      <div>
        <div class="mapcard">
          <div class="sectionhead"><h3>Riverside Office</h3><span class="pill">${state.placements.length} control${state.placements.length === 1 ? '' : 's'} deployed · ${money(spent())}</span></div>
          ${mapView()}
          <div class="zone-buttons">${ZONES.map(z =>
            `<button class="${zone === z[0] ? 'active' : ''}" aria-pressed="${zone === z[0]}" onclick="selectZone('${z[0]}')">${z[1]}</button>`).join('')}</div>
          <div class="purposes"><small>Control purposes covered</small><div>${purposeStrip}</div></div>
        </div>
        <h3 class="blockhead">Operational procedures <span class="spec" title="${esc(SPEC['C1'])}">C1</span></h3>
        <p class="tiny">Equipment on its own is not a control. Procedures cost money and staff time, and a procedure with nothing behind it does not count — so choose, do not tick everything. Running all seven costs ${money0(PROCEDURES.reduce((a, p) => a + p.cost, 0))} of your budget; you are spending ${money(procSpent())} on the ${c.procsOn} you have declared.</p>
        <div class="procedures">${PROCEDURES.map(p => {
          const on = !!state.procedures[p.id], gap = on && !supported(p.id), note = ownerNote(p.id);
          return `<div class="proc-card ${on ? 'on' : ''} ${gap ? 'unsupported' : ''}">
            <label class="procedure">
              <input type="checkbox" ${on ? 'checked' : ''} onchange="setProcedure('${p.id}', this.checked)">
              <span><b>${p.name}</b> <span class="cost">${money0(p.cost)}/yr</span><small>${p.desc}</small></span>
            </label>
            ${gap ? `<p class="gap-line">Nothing supports this yet. ${p.needsText} It will not count in an incident until it does.</p>` : ''}
            ${on ? `<label class="sr-only" for="own-${p.id}">Who owns ${p.name}?</label>
              <textarea id="own-${p.id}" class="owner" placeholder="Who owns this, and how would you know it is actually happening?" onchange="saveProcedureNote('${p.id}', this.value)">${esc(note)}</textarea>
              <span class="tiny">${note.length >= 25 ? '\u2713 Owner recorded' : 'Name the person or role, and the evidence that it happens'}</span>` : ''}
          </div>`;
        }).join('')}</div>
      </div>

      <section class="sidepanel">
        <span class="eyebrow">SELECTED ZONE</span>
        <h2>${zname(zone)}</h2>
        <p>${zinfo(zone)[6]}</p>
        ${stock.length ? `<form id="deployform" onsubmit="deploy(event)">
            <label for="equipment">Your research inventory</label>
            <select id="equipment" required>
              <option value="">Choose a product…</option>
              ${stock.map(x => `<option value="${x.t.id}:${x.k}"${x.t.zones.includes(zone) ? '' : ' data-odd="1"'}>${x.t.name} · ${esc(x.p.name)} · ${money(x.p.price)}${x.t.zones.includes(zone) ? '' : ' (unusual here)'}</option>`).join('')}
            </select>
            <label for="reason">Why this control, in this zone, from this supplier?</label>
            <textarea id="reason" minlength="20" required placeholder="Name the risk in this zone, say how the control reduces it, and say why you chose this supplier over the other one."></textarea>
            <button class="primary">Deploy to this zone</button>
          </form>`
        : `<div class="empty">Nothing to deploy yet.<br>Research a product to unlock it.<br><button style="margin-top:12px" onclick="setTab('research')">Open the research lab</button></div>`}
        <div class="installed">
          <h3>Installed here</h3>
          ${state.placements.filter(p => p.zone === zone).map(p => {
            const prod = state.products[p.type][p.slot], t = type(p.type);
            return `<div class="installed-item">
              <button onclick="removePlacement('${p.id}')" aria-label="Remove ${esc(t.name)} from ${esc(zname(zone))}">×</button>
              <b>${esc(prod.name)}</b>
              <span>${t.name} · ${GROUPS[t.group][0]} · ${money(prod.price)} ${specTag(t.spec)}</span>
              <p>${esc(p.reason)}</p></div>`;
          }).join('') || '<p class="tiny">No controls here yet. An empty zone is a gap an incident will find.</p>'}
        </div>
      </section>
    </div>`;
}

function setProcedure(id, on) {
  const p = proc(id);
  if (on && spent() + p.cost > state.budget) {
    toast('That procedure would take you over budget', {
      type: 'error',
      detail: `${p.name} costs ${money0(p.cost)} a year and you have ${money(state.budget - spent())} left. Procedures compete with equipment for the same money — that is the trade-off.`
    });
    render();
    return;
  }
  state.procedures[id] = on;
  if (!on) state.procedureNotes[id] = '';
  persist();
  render();

  if (!on) {
    toast(`Procedure removed: ${p.name}`, { type: 'warn', detail: `${money0(p.cost)} back in the budget. Any incident that relied on it will now show a gap.`, key: 'proc-' + id });
    return;
  }
  if (!supported(id)) {
    toast(`${p.name} has nothing behind it`, {
      type: 'warn',
      detail: `${p.needsText} You are paying ${money0(p.cost)} for a procedure that will not count until the equipment is there.`,
      duration: 9000,
      key: 'proc-' + id,
      action: { label: 'Research what it needs', run: () => setTab('research') }
    });
    return;
  }
  toast(`Procedure added: ${p.name}`, {
    type: 'ok',
    detail: `${money0(p.cost)} a year, ${money(state.budget - spent())} left. Now say who owns it.`,
    key: 'proc-' + id
  });
}

function saveProcedureNote(id, value) {
  state.procedureNotes[id] = value;
  persist();
  const p = proc(id);
  if (value.trim().length >= 25) {
    toast(`Owner recorded: ${p.name}`, { type: 'ok', detail: 'A policy nobody owns is a policy nobody follows — that is the C1 point.', key: 'own-' + id });
  } else if (value.trim().length) {
    toast('Owner statement too short', { type: 'warn', detail: 'Name the person or role and say how you would know it is happening.', key: 'own-' + id });
  }
  render();
}

function deploy(e) {
  e.preventDefault();
  const [id, k] = $('#equipment').value.split(':');
  const t = type(id), p = state.products[id]?.[Number(k)];
  if (!validProduct(p)) return;

  if (state.placements.some(x => x.type === id && x.zone === zone)) {
    toast(`${t.name} is already installed in ${zname(zone)}`, { type: 'warn', detail: 'Remove the existing one first if you want to swap supplier.' });
    return;
  }
  if (spent() + p.price > state.budget) {
    toast('That would take you over budget', {
      type: 'error',
      detail: `${esc(p.name)} costs ${money(p.price)} and you have ${money(state.budget - spent())} left. Remove a control, choose the cheaper supplier, or change the mission budget.`,
      action: { label: 'Open mission brief', run: () => setTab('brief') }
    });
    return;
  }

  state.placements.push({ id: crypto.randomUUID(), type: id, slot: Number(k), zone, reason: $('#reason').value });
  persist();
  render();

  const odd = !t.zones.includes(zone);
  toast(`Deployed to ${zname(zone)}`, {
    type: odd ? 'warn' : 'ok',
    detail: odd
      ? `${t.name} is not usually sited in ${zname(zone).toLowerCase()} — it normally protects ${t.zones.map(zname).join(', ').toLowerCase()}. Keep it if you can justify it; an examiner will want the reason.`
      : `${esc(p.name)} · ${money(p.price)} · ${money(state.budget - spent())} left.`,
    duration: odd ? 9000 : 5200,
    action: pairReady(id)
      ? { label: 'Test this zone', run: () => setTab('simulate') }
      : { label: 'Add the other supplier', run: () => editProduct(id, validProduct(state.products[id]?.[0]) ? 1 : 0) }
  });
}

function removePlacement(id) {
  const gone = state.placements.find(p => p.id === id);
  if (!gone) return;
  const before = PROCEDURES.filter(p => state.procedures[p.id] && supported(p.id)).map(p => p.id);
  state.placements = state.placements.filter(p => p.id !== id);
  persist();
  render();
  const broken = before.filter(pid => !supported(pid)).map(pid => proc(pid).name);
  toast(`Removed from ${zname(gone.zone)}`, {
    type: broken.length ? 'error' : 'warn',
    detail: `${type(gone.type).name} · ${money(state.budget - spent())} now available.`
      + (broken.length ? ` That was the only equipment behind ${broken.join(' and ')} — you are still paying for it, but it will not count in an incident until you put something back.` : ''),
    duration: broken.length ? 9000 : 5200,
    action: {
      label: 'Undo',
      run: () => {
        state.placements.push(gone);
        persist(); render();
        toast('Control restored', { type: 'ok', detail: `${type(gone.type).name} is back in ${zname(gone.zone)}.` });
      }
    }
  });
}

/* ---------------------------------------------------------------- research lab */

function researchView() {
  const c = counts();
  const ruleNote = state.researchRule === 'deployed'
    ? 'Every technique is listed below and you can research any of them now. The ones you deploy are the ones that must have two suppliers compared.'
    : 'You compare two suppliers for every technique in the pack, whether you deploy it or not.';

  return head('Know what you are buying.',
    'Source two real products from different suppliers, then write which one you would buy and why.',
    `<span class="pill">${c.compares} / ${c.required || 0} comparisons complete</span>`) +
    `<div class="notice">${ruleNote} <button class="link" onclick="toggleRule()">Switch to ${state.researchRule === 'deployed' ? 'every technique' : 'deployed techniques only'}</button></div>` +
    GROUPS.map((g, i) => {
      const items = TYPES.filter(t => t.group === i);
      return `<section class="category">
        <div class="category-title"><span class="tag">${i + 1}</span><h2>${g[0]} controls</h2></div>
        <p class="definition">${g[1]}</p>
        <div class="research-grid">${items.map(t => researchCard(t)).join('')}</div>
      </section>`;
    }).join('');
}

function researchCard(t) {
  const req = requiredTypes().includes(t.id);
  const a = state.products[t.id] || [];
  const done = compareReady(t.id);
  return `<article class="research-card ${done ? 'done' : ''} ${req ? '' : 'optional'}">
    <div class="rc-top"><h3>${t.name}</h3>${specTag(t.spec)}</div>
    <p>${t.blurb}</p>
    <p class="tiny">Normally protects: ${t.zones.map(zname).join(', ').toLowerCase()}.</p>
    ${examplesBlock(t.id)}
    <a class="tiny" href="https://www.google.com/search?q=${encodeURIComponent(t.search)}" target="_blank" rel="noopener noreferrer">Find UK suppliers</a>
    <div class="slots">${[0, 1].map(k =>
      `<button class="${validProduct(a[k]) ? 'complete' : ''}" onclick="editProduct('${t.id}',${k})">${validProduct(a[k]) ? '✓ ' + esc(a[k].supplier.slice(0, 16)) : '+ Supplier ' + (k + 1)}</button>`).join('')}</div>
    ${pairReady(t.id)
      ? `<label class="cmp-label" for="cmp-${t.id}">Which would you buy, and why?</label>
         <textarea id="cmp-${t.id}" class="cmp" placeholder="Compare price, specification, fitness for the zone and anything the cheaper option leaves out. At least 40 characters." onchange="saveCompare('${t.id}', this.value)">${esc(state.compare[t.id] || '')}</textarea>
         <span class="tiny">${done ? '✓ Comparison written' : 'Comparison still needed for the marks'}</span>`
      : `<span class="tiny">${req ? 'Two different suppliers needed.' : 'Not required unless you deploy this control.'}</span>`}
  </article>`;
}

function toggleRule() {
  state.researchRule = state.researchRule === 'deployed' ? 'all' : 'deployed';
  persist(); render();
  toast(state.researchRule === 'all' ? 'Researching every technique' : 'Researching deployed techniques only', {
    type: 'info',
    detail: state.researchRule === 'all'
      ? `All ${TYPES.length} techniques now count towards your clearance — ${TYPES.length * 2} product records.`
      : 'Only the controls you deploy need a two-supplier comparison. Your existing research is kept.'
  });
}

function saveCompare(id, value) {
  state.compare[id] = value;
  persist();
  if (compareReady(id)) {
    toast(`Comparison saved: ${type(id).name}`, { type: 'ok', detail: 'That is the supplier-choice justification the mark scheme asks for.', key: 'cmp-' + id });
  } else if (value.trim().length) {
    toast('Comparison too short to count', { type: 'warn', detail: 'Say which product you would buy and give a reason — 40 characters or more.', key: 'cmp-' + id });
  }
  render();
}

function editProduct(id, slot) {
  const t = type(id), p = state.products[id]?.[slot] || {};
  editImage = p.image || '';
  $('#dialog-body').innerHTML = `
    <div class="dialog-top">
      <div><span class="eyebrow">${GROUPS[t.group][0].toUpperCase()} · SUPPLIER ${slot + 1}</span><h2>${t.name}</h2></div>
      <button onclick="$('#editor').close()" aria-label="Close product form">✕</button>
    </div>
    <p class="tiny">Use a real supplier page. Your evidence is recorded here, not verified automatically — your teacher checks it. ${specTag(t.spec)}</p>
    ${examplesBlock(id)}
    <form id="productform">
      <div class="formgrid">
        <label>Product name<input name="name" required value="${esc(p.name)}"></label>
        <label>Supplier name<input name="supplier" required value="${esc(p.supplier)}"></label>
        <label class="full">Product page URL<input name="url" type="url" placeholder="https://…" required value="${esc(p.url)}"></label>
        <label>Price or quoted estimate (£)<input name="price" type="number" min="0" step="0.01" required value="${p.price ?? ''}">
          ${EXAMPLES[id] ? `<span class="tiny">Typical: ${exRange(id)}</span>` : ''}</label>
        <label>Price basis and date<input name="priceNote" placeholder="per unit, VAT included, checked 21 Sept" required value="${esc(p.priceNote)}"></label>
        <label class="full">What it does, and what it does not do<textarea name="description" required minlength="20" placeholder="Features, what it protects against, and one limitation.">${esc(p.description)}</textarea></label>
        <label class="full">Product image URL<input name="image" type="url" placeholder="https://… or attach a screenshot below" value="${weburl(editImage) ? esc(editImage) : ''}"></label>
        <label class="full">Or attach a screenshot (PNG, JPG or WebP, under 500 KB)<input id="productimage" type="file" accept="image/png,image/jpeg,image/webp"></label>
      </div>
      <div id="imagepreview">${imgurl(editImage) ? `<img class="previewimg" src="${esc(editImage)}" alt="Saved product evidence">` : ''}</div>
      <p class="tiny">For quote-only systems, label the figure as an estimate and say what it includes. Never invent a supplier quote.</p>
      <div id="formerror" class="error" role="alert"></div>
      <div class="dialog-actions">
        <span class="tiny">15 XP for a complete record</span>
        <button class="primary" type="submit">Save product evidence</button>
      </div>
    </form>`;

  $('#productimage').onchange = async e => {
    const f = e.target.files[0];
    if (!f) return;
    if (f.size > 500000 || !['image/png', 'image/jpeg', 'image/webp'].includes(f.type)) {
      toast('That image cannot be used', { type: 'error', detail: 'Choose a PNG, JPG or WebP under 500 KB. A cropped screenshot is usually well under that.' });
      return;
    }
    editImage = await new Promise(resolve => { const r = new FileReader(); r.onload = () => resolve(r.result); r.readAsDataURL(f); });
    $('#imagepreview').innerHTML = `<img class="previewimg" src="${esc(editImage)}" alt="Product evidence">`;
    $('#productform [name=image]').value = '';
    toast('Screenshot attached', { type: 'ok', detail: 'A screenshot is more reliable than a remote image link, which suppliers can block.' });
  };

  $('#productform').onsubmit = e => {
    e.preventDefault();
    const d = Object.fromEntries(new FormData(e.target));
    const p2 = { ...d, price: Number(d.price), image: d.image.trim() || editImage };
    const other = state.products[id]?.[1 - slot];
    if (!validProduct(p2)) {
      $('#formerror').textContent = 'Something is missing. Every record needs a valid supplier link, an image, a description, a price and the price basis.';
      return;
    }
    if (other?.supplier.trim().toLowerCase() === p2.supplier.trim().toLowerCase()) {
      $('#formerror').textContent = 'Use a different supplier for the second product — the point is to compare two sources.';
      return;
    }
    state.products[id] ??= [];
    state.products[id][slot] = p2;
    persist();
    $('#editor').close();
    render();
    const ex = EXAMPLES[id];
    if (ex && (p2.price < ex.low / 3 || p2.price > ex.high * 3)) {
      toast('That price is a long way outside the typical range', {
        type: 'warn',
        duration: 9000,
        detail: `${t.name} normally costs ${exRange(id)}. Check whether you have priced one unit or a whole system, and whether installation and VAT are in the figure. Keep it if you can justify it — just say what it includes.`
      });
    }
    toast(`Evidence saved: ${esc(p2.name)}`, {
      type: 'ok',
      detail: pairReady(id) ? 'Both suppliers recorded. Now write which one you would buy.' : 'Add a second supplier so you can compare.',
      action: pairReady(id) ? null : { label: 'Add supplier ' + (2 - slot), run: () => editProduct(id, 1 - slot) }
    });
  };

  $('#editor').showModal();
}

/* ---------------------------------------------------------------- simulator */

function simView() {
  const results = latestRuns();
  const done = results.filter(r => r.score === 100).length;
  return head('Put your plan under pressure.',
    'Run an incident, read the debrief and go back and fix what it found. Re-running an unchanged design does not earn more XP.',
    `<span class="pill">${done} / ${SCENARIOS.length} fully addressed</span>`) +
    `<div class="notice">These are transparent classroom scenarios, not real-world predictions. A full score means the checks listed for that scenario are met. Whether the product you chose is actually suitable, covers the right area and is installed properly is for you and your teacher to judge.</div>
    ${staleRuns() ? `<div class="notice warning">Some results below are from an earlier version of your design. Run those incidents again.</div>` : ''}
    <div class="scenario-grid">${SCENARIOS.map((s, i) => {
      const r = results.find(x => x.id === s[0]);
      const stale = !r && state.runs.some(x => x.id === s[0]);
      return `<article class="card scenario">
        <span class="number">${String(i + 1).padStart(2, '0')}</span>
        <span class="pill">${r ? r.score + '%' : stale ? 'Retest' : 'Untested'}</span>
        <h3>${s[1]}</h3>
        <p>${s[2]}</p>
        <div class="scen-foot">${specTag([s[4]])}<span class="tiny">${zname(s[3])}</span></div>
        <button class="${r?.score === 100 ? '' : 'primary'}" onclick="runIncident('${s[0]}')" ${running ? 'disabled' : ''}>${running ? 'Testing…' : 'Run incident'}</button>
      </article>`;
    }).join('')}</div>
    ${activeRun ? resultView(activeRun) : ''}`;
}

function resultView(r) {
  const s = SCENARIOS.find(x => x[0] === r.id);
  const gaps = r.checks.filter(c => !c.ok);
  return `<section class="card results" id="result">
    <div class="sectionhead">
      <div><span class="eyebrow">INCIDENT DEBRIEF</span><h2>${s[1]}</h2><p class="tiny">Specification link: ${esc(SPEC[s[4]] || s[4])}</p></div>
      <div class="bigscore ${r.score === 100 ? 'full' : ''}">${r.score}<span>%</span></div>
    </div>
    ${mapView(s[3])}
    <div>${r.checks.map(c => `<div class="resultrow ${c.ok ? '' : 'fail'}">
      <span class="outcome">${c.ok ? '✓' : '!'}</span>
      <div><b>${c.ok ? 'Addressed' : 'Gap in the design'}</b><p>${c.text}</p>${c.why ? `<p class="tiny">${c.why}</p>` : ''}</div></div>`).join('')}</div>
    <p class="tiny" style="margin-top:14px">${r.signature === signature() ? 'This result matches your current design.' : 'Your design has changed since this test. Run it again.'} The model checks control types, zones and declared procedures — not lock ratings, camera coverage, gas suitability or installation quality.</p>
    <button style="margin-top:16px" onclick="selectZone('${s[3]}');setTab('plan')">Improve ${zname(s[3]).toLowerCase()}</button>
    ${gaps.length ? `<button style="margin-top:16px" onclick="setTab('research')">Research what is missing</button>` : ''}
  </section>`;
}

async function runIncident(id) {
  if (running) return;
  if (!state.placements.length) {
    toast('Nothing to test yet', { type: 'warn', detail: 'Deploy at least one researched control before running an incident.', action: { label: 'Open the planner', run: () => setTab('plan') } });
    return;
  }
  running = true; tab = 'simulate'; activeRun = null; render();
  const s = SCENARIOS.find(x => x[0] === id);
  toast(`Running: ${s[1]}`, { type: 'info', detail: `Checking your layers of defence around ${zname(s[3]).toLowerCase()}…`, duration: 2500 });
  await new Promise(r => setTimeout(r, 850));

  const before = latestRuns().filter(r => r.score === 100).length;
  const result = evaluate(id);
  const run = { ...result, id, date: new Date().toISOString(), signature: signature() };
  state.runs.push(run);
  state.runs = state.runs.slice(-120);
  activeRun = run;
  running = false;
  persist();
  render();
  $('#result')?.scrollIntoView({ behavior: 'smooth', block: 'start' });

  const gaps = run.checks.filter(c => !c.ok);
  if (run.score === 100) {
    const after = latestRuns().filter(r => r.score === 100).length;
    toast(`${s[1]}: fully addressed`, {
      type: 'xp',
      detail: after > before ? `+60 XP. ${after} of ${SCENARIOS.length} incidents now covered by your current design.` : 'Already credited for this design.'
    });
  } else {
    toast(`${s[1]}: ${run.score}%`, {
      type: 'warn',
      detail: `${gaps.length} gap${gaps.length === 1 ? '' : 's'}. First one: ${gaps[0].text}`,
      duration: 9000,
      action: { label: `Fix ${zname(s[3]).toLowerCase()}`, run: () => { selectZone(s[3]); setTab('plan'); } }
    });
  }
}

function evaluate(id) {
  /* a procedure only counts when the design actually supports it */
  const p = Object.fromEntries(PROCEDURES.map(x => [x.id, declared(x.id)]));
  const c = (ok, text, why) => ({ ok: !!ok, text, why });
  let checks;
  switch (id) {
    case 'tailgate': checks = [
      c(has('badges', 'reception'), 'Staff and visitors have identification to display at reception.', 'Directive control: it only works if people can tell staff from strangers at a glance.'),
      c(has('signs', 'reception'), 'Reception signage states the sign-in and escort rules.'),
      c(has('access', 'reception'), 'The door from reception into the office needs a card or code.', 'Without it the public area and the staff area are the same space.'),
      c(p.visitor, 'Staff sign visitors in, badge them and escort them.', 'Badges alone do not stop tailgating. Someone has to be willing to challenge.')]; break;
    case 'vehicle': checks = [
      c(has('barriers', 'perimeter'), 'Barriers or bollards keep vehicles off the site.'),
      c(has('gates', 'perimeter'), 'A controlled gate protects the entry point.'),
      c(has('signs', 'perimeter'), 'Boundary signage makes the restriction clear.'),
      c(has('cctv', 'perimeter') && p.response, 'Perimeter CCTV is paired with a named responder.', 'A camera nobody watches is evidence, not detection.')]; break;
    case 'server': checks = [
      c(has('locks', 'server') || has('access', 'server'), 'The server-room door is locked or card-controlled.'),
      c(has('cages', 'server'), 'A cabinet or cage adds a second layer around the equipment.'),
      c(has('biometric', 'server') || has('access', 'server'), 'Entry to the room is identified to a person, not just to a key.', 'A key says the door opened. A card or biometric says who opened it.'),
      c((has('motion', 'server') || has('cctv', 'server')) && p.response, 'Detection in the room is backed by a response procedure.')]; break;
    case 'records': checks = [
      c(has('locks', 'records') || has('access', 'records'), 'The records store is locked or card-controlled.'),
      c(has('motion', 'records'), 'Movement in the records store is detected out of hours.'),
      c(has('mediasafe', 'records'), 'Confidential files and backup media are in a secure cabinet or safe.'),
      c(p.response, 'A named responder investigates the alert.')]; break;
    case 'delivery': checks = [
      c(has('locks', 'delivery') || has('access', 'delivery'), 'The service entrance is locked or card-controlled.'),
      c(has('signs', 'delivery') && p.visitor, 'Contractor instructions are backed by staff signing people in.'),
      c(has('cctv', 'delivery') && p.response, 'Delivery-entrance CCTV has an active response procedure.')]; break;
    case 'laptop': checks = [
      c(has('devicelock', 'office'), 'Laptops and equipment in the open office are physically secured or marked.'),
      c(has('cctv', 'office'), 'The open-plan area is covered by CCTV for evidence.'),
      c(has('badges', 'reception') && p.visitor, 'Anyone in the office without a badge can be identified and challenged.')]; break;
    case 'leaver': checks = [
      c(has('access', 'reception'), 'Entry uses cards or codes that can be revoked centrally.', 'Metal keys cannot be revoked. If a key goes missing you have to change the lock.'),
      c(p.keys, 'Keys and cards are logged, returned and revoked when someone leaves.'),
      c(has('badges', 'reception'), 'Badges make an out-of-date holder visible to staff.'),
      c(has('cctv', 'reception') && p.response, 'Reception CCTV and a responder would pick up an unexpected entry.')]; break;
    case 'flood': checks = [
      c(has('flood', 'delivery'), 'Flood defence covers the delivery entry route.'),
      c(has('flood', 'plant'), 'Flood defence covers the plant area.'),
      c(has('flood', 'server'), 'Critical equipment has local flood protection.'),
      c(p.backups, 'Backups are held offsite, so a flood does not take the data with the building.')]; break;
    case 'fire': checks = [
      c(has('fire', 'office'), 'Fire-suppression equipment suited to the hazard is in the office.'),
      c(p.fireplan, 'A trained response and evacuation procedure supports the equipment.', 'Evacuation comes first. Equipment is for trained staff and small fires only.'),
      c(p.backups, 'Offsite backups mean the business survives the loss of the room.')]; break;
    case 'gas': checks = [
      c(has('gas', 'server'), 'A suitable suppression system protects the enclosed server room.'),
      c(p.fireplan, 'Safe evacuation and a trained response are planned.', 'Gas systems need a clear room. The procedure is part of the control.'),
      c(p.backups, 'Backups are offsite in case the room is lost.')]; break;
    case 'heat': checks = [
      c(has('cooling', 'server'), 'Primary cooling addresses the normal overheating risk.'),
      c(has('backupcool', 'server'), 'Standby cooling is available when the primary fails.', 'This is the compensating control: it substitutes for cooling that is unavailable.'),
      c(p.coolplan, 'Temperature is monitored and staff know how to switch over.')]; break;
    case 'power': checks = [
      c(has('power', 'server'), 'A UPS keeps critical equipment running or shuts it down cleanly.'),
      c(p.backups, 'Recent backups exist offsite in case data is corrupted by the outage.'),
      c(p.coolplan, 'Staff know cooling stops with the power and monitor temperature.')]; break;
    default: throw Error('Unknown incident');
  }
  return { checks, score: Math.round(checks.filter(x => x.ok).length / checks.length * 100) };
}

/* ---------------------------------------------------------------- exam practice */

function examView() {
  const totalMarks = QUESTIONS.reduce((a, q) => a + q.marks, 0);
  const awarded = QUESTIONS.reduce((a, q) => a + (state.answers[q.id]?.mark ?? 0), 0);
  const marked = QUESTIONS.filter(q => state.answers[q.id]?.mark != null).length;

  return head('Answer it the way the exam asks.',
    'Unit 2 is assessed by written examination. These questions use the same command words and are set against the design you built.',
    `<span class="pill">${counts().answered} / ${QUESTIONS.length} answered</span>`) +
    `<div class="notice">Write in full sentences. <b>Identify</b> wants a name only. <b>Describe</b> wants what it is and what it does. <b>Explain</b> wants a reason or a consequence — usually the word "because" or "so that". <b>Evaluate</b> wants both sides and a judgement you commit to. Marks you award yourself are for tracking only; your teacher marks the real thing.</div>
    ${marked ? `<div class="reportgrid"><div class="card"><strong>${awarded}/${totalMarks}</strong><small>Self-assessed marks on ${marked} question${marked === 1 ? '' : 's'}</small></div></div>` : ''}
    ${QUESTIONS.map((q, i) => {
      const a = state.answers[q.id] || {};
      const len = (a.text || '').trim().length;
      return `<section class="card question">
        <div class="q-top">
          <span class="cmdword">${q.cmd}</span>
          <span class="pill">${q.marks} mark${q.marks === 1 ? '' : 's'}</span>
          ${specTag([q.spec])}
        </div>
        <h3>${i + 1}. ${q.prompt}</h3>
        <label class="sr-only" for="ans-${q.id}">Your answer to question ${i + 1}</label>
        <textarea id="ans-${q.id}" class="answer" placeholder="Write your answer here." onchange="saveAnswer('${q.id}', this.value)">${esc(a.text || '')}</textarea>
        <div class="q-foot">
          <span class="tiny">${len ? len + ' characters' : 'Not started'}${len && len < 30 ? ' — too short to count' : ''}</span>
          <span>
            <button onclick="revealMarks('${q.id}')">${a.revealed ? 'Hide' : 'Show'} indicative content</button>
            <label class="inline-mark">Self-assessed mark
              <input type="number" min="0" max="${q.marks}" value="${a.mark ?? ''}" onchange="saveMark('${q.id}', this.value)"> / ${q.marks}
            </label>
          </span>
        </div>
        ${a.revealed ? `<div class="markscheme"><b>What a marker is looking for</b><ul>${q.indicative.map(x => `<li>${x}</li>`).join('')}</ul></div>` : ''}
      </section>`;
    }).join('')}`;
}

function saveAnswer(id, text) {
  const q = QUESTIONS.find(x => x.id === id);
  state.answers[id] = { ...(state.answers[id] || {}), text };
  persist();
  const len = text.trim().length;
  if (len >= 30) {
    toast(`Answer saved: question ${QUESTIONS.indexOf(q) + 1}`, {
      type: 'ok',
      detail: `${q.cmd} question, ${q.marks} marks. Compare it against the indicative content before you move on.`,
      key: 'ans-' + id,
      action: { label: 'Show indicative content', run: () => revealMarks(id, true) }
    });
  } else if (len) {
    toast('Answer too short to count', { type: 'warn', detail: `A ${q.marks}-mark ${q.cmd.toLowerCase()} question needs more than a few words.`, key: 'ans-' + id });
  }
  render();
}

function saveMark(id, value) {
  const q = QUESTIONS.find(x => x.id === id);
  const n = value === '' ? null : Math.max(0, Math.min(q.marks, Number(value)));
  state.answers[id] = { ...(state.answers[id] || {}), mark: n };
  persist();
  if (n != null) toast(`Mark recorded: ${n}/${q.marks}`, { type: 'info', detail: n < q.marks ? 'Read the indicative content and add what is missing.' : 'Full marks — check you covered every bullet in the indicative content.', key: 'mark-' + id });
  render();
}

function revealMarks(id, force) {
  state.answers[id] = { ...(state.answers[id] || {}), revealed: force ? true : !state.answers[id]?.revealed };
  render();
}

/* ---------------------------------------------------------------- report */

function coverage() {
  const hit = new Set();
  state.placements.forEach(p => type(p.type).spec.forEach(s => hit.add(s)));
  PROCEDURES.forEach(p => { if (declared(p.id)) p.spec.forEach(code => hit.add(code)); });
  QUESTIONS.forEach(q => { if ((state.answers[q.id]?.text || '').trim().length >= 30) hit.add(q.spec); });
  return Object.keys(SPEC).map(code => [code, SPEC[code], hit.has(code)]);
}

function reportView() {
  const c = counts(), r = latestRuns();
  const awarded = QUESTIONS.reduce((a, q) => a + (state.answers[q.id]?.mark ?? 0), 0);
  const totalMarks = QUESTIONS.reduce((a, q) => a + q.marks, 0);

  return head('Your security case.',
    'Everything you researched, decided, tested and evaluated, in one place.',
    `<button class="primary" onclick="printReport()">Print or save as PDF</button>`) +
    `<div class="reportgrid">
      <div class="card"><strong>${c.compares}/${c.required || 0}</strong><small>Supplier comparisons written</small></div>
      <div class="card"><strong>${c.wins}/${SCENARIOS.length}</strong><small>Incidents fully addressed</small></div>
      <div class="card"><strong>${money(spent())}</strong><small>Of ${money(state.budget)} — ${money(equipSpent())} equipment, ${money(procSpent())} procedures</small></div>
      <div class="card"><strong>${awarded}/${totalMarks}</strong><small>Self-assessed exam marks</small></div>
    </div>

    <div class="card">
      <label for="team">Student or team name</label>
      <input id="team" value="${esc(state.team)}" onchange="saveTeam(this.value)">
      <h3 class="blockhead">Clearance checklist</h3>
      <ul class="checklist">
        <li>${c.required && c.compares === c.required ? '✓' : '○'} Two suppliers compared, with a written choice, for every technique you use (${c.compares}/${c.required || 0}).</li>
        <li>${c.purposes.every(Boolean) ? '✓' : '○'} At least one control of each purpose deployed (${c.purposes.filter(Boolean).length}/5).</li>
        <li>${c.wins === SCENARIOS.length ? '✓' : '○'} All ${SCENARIOS.length} incidents fully addressed by the current design.</li>
        <li>${counts().procsOn && counts().procsOn === counts().procsDone ? '✓' : '○'} Every declared procedure is supported by equipment and has a named owner (${counts().procsDone}/${counts().procsOn || 0}).</li>
        <li>${spent() <= state.budget ? '✓' : '○'} Equipment and procedures together within the ${money(state.budget)} budget.</li>
        <li>${c.answered === QUESTIONS.length ? '✓' : '○'} All ${QUESTIONS.length} exam-practice questions answered.</li>
        <li>${state.reflection.trim().length >= 120 ? '✓' : '○'} Final evaluation written.</li>
      </ul>
      <label for="reflection">Final evaluation</label>
      <textarea id="reflection" oninput="state.reflection=this.value" onchange="saveReflection()" placeholder="Which supplier gave better value, and why? Which risk is still open? What does your compensating control stand in for? What would you buy next with another £2,000?">${esc(state.reflection)}</textarea>
    </div>

    <div class="card" style="margin-top:20px">
      <h2>Specification coverage</h2>
      <p class="tiny">Unit 2: Cyber Security and Incident Management. Based on the controls you deployed, the procedures you declared and the questions you answered.</p>
      <ul class="coverage">${coverage().map(([code, label, on]) => `<li class="${on ? 'on' : ''}"><span>${on ? '✓' : '○'}</span> ${label}</li>`).join('')}</ul>
    </div>

    <div class="card" style="margin-top:20px">
      <h2>Your floorplan</h2>
      ${mapView()}
      <h3 class="blockhead">Deployment decisions</h3>
      ${state.placements.map(p => {
        const prod = state.products[p.type][p.slot], t = type(p.type);
        return `<p><b>${zname(p.zone)} — ${t.name} (${GROUPS[t.group][0]}):</b> ${esc(prod.name)}, ${esc(prod.supplier)}, ${money(prod.price)}. ${esc(p.reason)}</p>`;
      }).join('') || '<p>No controls deployed.</p>'}
      <h3 class="blockhead">Operational procedures</h3>
      ${PROCEDURES.filter(p => state.procedures[p.id]).map(p => `<p><b>${p.name} — ${money0(p.cost)}/yr${supported(p.id) ? '' : ' — NOT SUPPORTED BY THE DESIGN'}:</b> ${p.desc}<br>${ownerNote(p.id) ? 'Owner: ' + esc(ownerNote(p.id)) : '<i>No owner recorded.</i>'}</p>`).join('') || '<p>No procedures declared. Every incident that depends on staff action will show a gap.</p>'}
    </div>

    <div class="card" style="margin-top:20px">
      <h2>Incident results</h2>
      ${r.map(x => {
        const s = SCENARIOS.find(y => y[0] === x.id);
        return `<p><b>${s[1]} — ${x.score}%</b><br>${x.checks.map(ch => `${ch.ok ? '✓' : 'Gap:'} ${esc(ch.text)}`).join('<br>')}</p>`;
      }).join('') || '<p>No results for the current design. Run the incidents after your final changes.</p>'}
    </div>

    <div class="card" style="margin-top:20px">
      <h2>Exam practice</h2>
      ${QUESTIONS.map((q, i) => {
        const a = state.answers[q.id] || {};
        return `<p><b>${i + 1}. ${q.cmd} (${q.marks} marks)</b> — ${q.prompt}<br>${a.text ? esc(a.text) : '<i>Not answered.</i>'}${a.mark != null ? `<br><small>Self-assessed: ${a.mark}/${q.marks}</small>` : ''}</p>`;
      }).join('')}
    </div>

    <div class="card" style="margin-top:20px">
      <h2>Research evidence</h2>
      ${TYPES.filter(t => (state.products[t.id] || []).some(validProduct)).map(t => `
        <h3 class="blockhead">${GROUPS[t.group][0]} — ${t.name}</h3>
        ${(state.products[t.id] || []).filter(validProduct).map(p => `<div class="resultrow">
          <img src="${esc(p.image)}" alt="${esc(p.name)}" style="width:34px;max-height:70px;object-fit:contain">
          <div><b>${esc(p.name)} — ${esc(p.supplier)} — ${money(p.price)}</b>
          <p>${esc(p.description)}</p><p class="tiny">${esc(p.priceNote)}</p>
          <a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer">${esc(p.url)}</a></div></div>`).join('')}
        ${state.compare[t.id] ? `<p><b>Supplier choice:</b> ${esc(state.compare[t.id])}</p>` : ''}
      `).join('') || '<p>No research recorded yet.</p>'}
    </div>`;
}

function saveTeam(v) { state.team = v; persist(); toast('Name saved', { type: 'ok', detail: 'It will appear on the printed report.' }); }
function saveReflection() {
  persist();
  const len = state.reflection.trim().length;
  toast(len >= 120 ? 'Evaluation saved' : 'Evaluation saved, but it is short', {
    type: len >= 120 ? 'ok' : 'warn',
    detail: len >= 120 ? 'That completes the written part of your clearance.' : 'An evaluate answer needs both sides and a judgement. Aim for 120 characters or more.',
    key: 'reflection'
  });
  render();
}
function printReport() {
  toast('Opening the print dialogue', { type: 'info', detail: 'Choose "Save as PDF" as the destination to keep a copy with your coursework.', duration: 3500 });
  setTimeout(() => window.print(), 400);
}

/* ---------------------------------------------------------------- briefing */

function briefView() {
  return head('The mission briefing.',
    'A 24-person office with public access, valuable equipment, confidential records and a river at the back.') +
    `<div class="grid2">
      <section class="card">
        <span class="eyebrow">WHAT YOU DO</span>
        <h2>Research. Deploy. Test. Evaluate.</h2>
        <ol class="checklist">
          <li>Research two products from different suppliers for each technique you want to use, and record price, basis, link, image and limitations.</li>
          <li>Write which supplier you would buy from and why.</li>
          <li>Place controls on the plan and justify the zone as well as the product.</li>
          <li>Tick the procedures that make the equipment work in practice.</li>
          <li>Run all ${SCENARIOS.length} incidents, read the gaps and revise the design.</li>
          <li>Answer the exam-practice questions and write your evaluation.</li>
        </ol>
        <label>Mission budget (£)<input type="number" min="0" max="1000000" step="100" value="${state.budget}" onchange="setBudget(this.value)"></label>
        <p>£14,000 is a classroom constraint, not a recommended real-world figure. A design that fully addresses all ${SCENARIOS.length} incidents needs about ${CLEARANCE_PLACEMENTS} controls plus procedures: near the bottom of the typical price ranges that is roughly £7,000, at mid-range prices roughly £11,000. Lower it to force harder trade-offs; raise it if students are pricing installed or quoted systems rather than single units.</p>
        <p>Procedures are charged against the same budget at an indicative annual cost — training, staff time, keyholding, offsite storage and destruction contracts are all real line items. All seven come to ${money0(PROCEDURES.reduce((a, p) => a + p.cost, 0))}. The figures are classroom estimates, not quotes.</p>
        <label for="rulepick">Research requirement</label>
        <select id="rulepick" onchange="setRule(this.value)">
          <option value="deployed" ${state.researchRule === 'deployed' ? 'selected' : ''}>Compare suppliers for the techniques you deploy</option>
          <option value="all" ${state.researchRule === 'all' ? 'selected' : ''}>Compare suppliers for all ${TYPES.length} techniques (${TYPES.length * 2} records)</option>
        </select>
      </section>

      <section class="card">
        <span class="eyebrow">HOW IT IS SCORED</span>
        <h2>Earn your clearance.</h2>
        <ul class="checklist">
          <li>15 XP for each complete product record.</li>
          <li>25 XP for each two-supplier comparison with a written choice.</li>
          <li>15 XP for each deployment.</li>
          <li>60 XP for each incident fully addressed by your current design — testing is worth more than paperwork.</li>
          <li>10 XP for each exam question answered.</li>
          <li>10 XP for each procedure that is supported by the design and has a named owner.</li>
        </ul>
        <p>Changing the design makes old incident results historical — retest to earn the XP again. Repeating an identical run does not stack points.</p>
        <p>Every change autosaves in this browser straight away, so closing the tab by accident loses nothing — the header shows the time of the last save. The browser is the only place it lives, though: use <b>Save file</b> before changing computer, and if the machine is shared, before someone resets it.</p>
        <h3 class="blockhead">Where this sits in Unit 2</h3>
        <ul class="coverage">${Object.entries(SPEC).map(([c, l]) => `<li class="on"><span>·</span> ${l}</li>`).join('')}</ul>
        <p class="tiny">Pearson Level 3 AAQ BTEC National in Information Technology, Unit 2: Cyber Security and Incident Management. Externally assessed by written examination.</p>
      </section>
    </div>

    <section class="card" style="margin-top:20px">
      <h2>The five control purposes</h2>
      ${GROUPS.map((g, i) => `<h3 class="blockhead">${g[0]}</h3><p>${g[1]} In this pack: ${TYPES.filter(t => t.group === i).map(t => t.name.toLowerCase()).join(', ')}.</p>`).join('')}
      <div class="notice" style="margin-top:20px">A control can serve more than one purpose depending on how it is used. Cooling normally prevents overheating; standby cooling is compensating only when it stands in for a primary control that has failed. A policy that ID must be displayed is directive; buying lanyards is not.</div>
      <h3 class="blockhead">Why procedures are not free</h3>
      <p>A policy costs money and depends on equipment. Declaring alarm response with no CCTV or sensors buys you a rota with nothing to respond to, so the simulation will not credit it. Every procedure you declare needs a named owner and a way of knowing it actually happens — that is the difference between a policy and a document.</p>
      <h3 class="blockhead">What the simulation does not check</h3>
      <p>It checks control types, zones and declared procedures. It does not check lock ratings, camera fields of view, flood heights, gas-system suitability, installation quality, price accuracy or whether staff would really follow the procedure. Keep escape routes usable in every design — physical security never overrides fire safety.</p>
      <h3 class="blockhead">Teacher controls</h3>
      <div class="teacher-row">
        <button onclick="exportWork()">Save file</button>
        <button onclick="document.querySelector('#import').click()">Open file</button>
        <button class="danger" onclick="resetAll()">Reset this device</button>
      </div>
    </section>`;
}

function setBudget(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || n > 1000000) { toast('Budget not changed', { type: 'error', detail: 'Enter a figure between £0 and £1,000,000.' }); render(); return; }
  state.budget = n;
  persist(); render();
  const over = spent() > state.budget;
  toast(`Budget set to ${money(n)}`, {
    type: over ? 'warn' : 'ok',
    detail: over ? `Your design costs ${money(spent())}, which is ${money(spent() - n)} over. Remove a control or raise the budget.` : `${money(n - spent())} available to spend.`
  });
}
function setRule(v) { if (v !== state.researchRule) toggleRule(); }

function resetAll() {
  if (!confirm('Delete all work stored in this browser? This cannot be undone. Save a file first if you need it.')) return;
  try { localStorage.removeItem(STORE_KEY); localStorage.removeItem(LEGACY_KEY); } catch (e) { }
  state = fresh(); activeRun = null; tab = 'plan'; zone = 'reception'; lastRank = '';
  render();
  toast('This device has been reset', { type: 'info', detail: 'A fresh mission is ready for the next student.' });
}

/* ---------------------------------------------------------------- files */

function exportWork() {
  const b = new Blob([JSON.stringify(state, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(b), a = document.createElement('a');
  a.href = url;
  a.download = (state.team ? state.team.replace(/[^a-z0-9]+/gi, '-').toLowerCase() + '-' : '') + 'secure-the-office.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  toast('Save file downloaded', { type: 'ok', detail: 'Keep it with your coursework. Open it on any computer to carry on.' });
}

/* ---------------------------------------------------------------- start */

function boot() {
  $('#import').onchange = async e => {
    const f = e.target.files[0];
    if (!f) return;
    try {
      if (f.size > 15000000) throw Error('the file is too large');
      const next = validateState(JSON.parse(await f.text()));
      if (!confirm('Replace the work on this device with this saved mission?')) { toast('Nothing was changed', { type: 'info' }); return; }
      state = next; activeRun = null; lastRank = '';
      persist(); render();
      toast('Mission restored', { type: 'ok', detail: `${state.placements.length} control(s) deployed, ${money(spent())} spent. Incident results are re-run against this design.` });
    } catch (err) {
      toast('That file could not be opened', { type: 'error', detail: String(err.message || err) + '. Choose the JSON file this app downloaded, not a screenshot or document.' });
    } finally { $('#import').value = ''; }
  };

  setSaved(localStorage.getItem(STORE_KEY) ? 'Autosaved in this browser' : 'Autosaves as you work');
  render();
  lastRank = rankName();

  if (!state.placements.length && !Object.keys(state.products).length) {
    setTimeout(() => toast('Welcome to the Riverside Office', {
      type: 'info',
      detail: 'Start in the research lab: find a real product, then deploy it on the plan and test it.',
      duration: 9000,
      action: { label: 'Read the brief', run: () => setTab('brief') }
    }), 700);
  }
}

boot();

if (document.modelContext?.registerTool) {
  Promise.resolve(document.modelContext.registerTool({
    name: 'read_security_mission',
    description: 'Read research progress, deployed controls and current incident results.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, untrustedContentHint: true },
    execute: () => ({
      progress: counts(),
      remainingBudget: state.budget - spent(),
      placements: state.placements,
      currentResults: latestRuns().map(r => ({ id: r.id, score: r.score, checks: r.checks }))
    })
  })).catch(() => { });
}
