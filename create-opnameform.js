/**
 * Script: create-opnameform.js
 * Maakt het "Opnameformulier 2.0" aan in AquaApp via de API.
 * Draai dit éénmalig vanuit C:\Projects\AquaApp:
 *   node create-opnameform.js
 */

const https = require('https');
const http = require('http');

// ─── INSTELLINGEN ─────────────────────────────────────────────────────────────
const BASE_URL = 'https://aquaapp2-0.onrender.com'; // of 'http://localhost:3000' voor lokaal
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';
// ──────────────────────────────────────────────────────────────────────────────

function request(method, url, body, token) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { 'Authorization': `Bearer ${token}` } : {})
      }
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function run() {
  console.log('🔑 Inloggen als admin...');
  const login = await request('POST', `${BASE_URL}/api/login`, {
    username: ADMIN_USER,
    password: ADMIN_PASS
  });

  if (login.status !== 200) {
    console.error('❌ Inloggen mislukt:', login.body);
    process.exit(1);
  }
  const token = login.body.token;
  console.log('✅ Ingelogd.\n');

  // ─── FORMULIER DEFINITIE ────────────────────────────────────────────────────
  const form = {
    name: 'Opnameformulier 2.0',
    email: 'r.zijlstra@aqua.nl', // ontvanger van de mail
    allowedUsers: [],             // wordt later ingesteld via admin panel
    fields: [
      {
        id: 'f_datum',
        type: 'date',
        label: 'Opnamedatum',
        required: true
      },
      {
        id: 'f_email',
        type: 'email',
        label: 'E-mailadres monteur',
        required: true
      },
      {
        id: 'h_stap1',
        type: 'heading',
        label: 'Stap 1 – Locatie en regio\nSelecteer de juiste gegevens voordat je verder gaat.',
        required: false
      },
      {
        id: 'f_locatie',
        type: 'list',
        label: 'Selecteer de servicelocatie',
        required: true,
        listId: '' // in te stellen via admin panel na het uploaden van de klantenlijst
      },
      {
        id: 'f_regio',
        type: 'multiselect',
        label: 'Geef aan voor welke regio deze opname is',
        required: true,
        options: ['Regio Noord', 'Regio Zuid', 'Regio Oost', 'Regio West', 'Regio Midden']
      },
      {
        id: 'h_stap2',
        type: 'heading',
        label: 'Stap 2 – Probleemomschrijving\nBeschrijf het probleem zo duidelijk mogelijk:\n• Wat is er aan de hand?\n• Waar bevindt het probleem zich?\n• Wanneer is het ontstaan (indien bekend)?',
        required: false
      },
      {
        id: 'f_probleem',
        type: 'textarea',
        label: 'Probleemomschrijving',
        required: true
      },
      {
        id: 'h_stap3',
        type: 'heading',
        label: 'Stap 3 – Status installatie\nBeoordeel de huidige situatie.',
        required: false
      },
      {
        id: 'f_functioneel',
        type: 'multiselect',
        label: 'Is de installatie volledig functioneel en inzetbaar?',
        required: true,
        options: ['Ja', 'Nee']
      },
      {
        id: 'h_stap4',
        type: 'heading',
        label: 'Stap 4 – Technische gegevens\nVul de technische specificaties zo volledig mogelijk in.',
        required: false
      },
      {
        id: 'f_diameter',
        type: 'multiselect',
        label: 'Diameter',
        required: true,
        options: ['N.v.t.', 'DN15', 'DN25', 'DN50', 'DN65', 'DN100', 'DN150', 'DN200', 'Anders']
      },
      {
        id: 'f_inbouwmaat',
        type: 'text',
        label: 'Inbouwmaat',
        required: true
      },
      {
        id: 'f_aansluitingen',
        type: 'multiselect',
        label: 'Aansluitingen',
        required: true,
        options: ['N.v.t.', 'Schroefdraad', 'Flens', 'Victaulic', 'Las', 'Anders']
      },
      {
        id: 'f_afwerking',
        type: 'multiselect',
        label: 'Afwerking',
        required: true,
        options: ['N.v.t.', 'Zwart', 'Menie', 'Verzinkt', 'Gelakt (RAL-kleur)', 'RVS', 'Anders']
      },
      {
        id: 'h_stap5',
        type: 'heading',
        label: 'Stap 5 – Middelen en bereikbaarheid\nGeef aan wat nodig is om het werk uit te voeren.',
        required: false
      },
      {
        id: 'f_middelen',
        type: 'multiselect',
        label: 'Middelen en bereikbaarheid',
        required: true,
        options: ['N.v.t.', 'Trap', 'Steiger', 'Hoogwerker', 'Anders']
      },
      {
        id: 'h_stap6',
        type: 'heading',
        label: "Stap 6 – Foto's toevoegen (verplicht)\nVoeg de volgende foto's toe:\n• Detailfoto (verplicht)\n• Afstandsfoto (verplicht)\n• Typeplaatje (indien mogelijk)\n\n⚠️ Zonder duidelijke foto's wordt de opname niet verwerkt.",
        required: false
      },
      {
        id: 'f_fotos',
        type: 'photo',
        label: "Foto's (detailfoto, afstandsfoto, typeplaatje)",
        required: true
      },
      {
        id: 'h_stap8',
        type: 'heading',
        label: 'Stap 7 – Controle en afronding\nControleer voor het indienen:\n✓ Zijn alle velden ingevuld?\n✓ Is de informatie duidelijk en volledig?\n✓ Zijn de foto\'s toegevoegd?\n\n💡 Denk alsof iemand anders jouw werk moet voorbereiden zonder jou te spreken.',
        required: false
      },
      {
        id: 'f_handtekening',
        type: 'signature',
        label: 'Handtekening monteur',
        required: false
      }
    ]
  };
  // ────────────────────────────────────────────────────────────────────────────

  console.log(`📋 Aanmaken: "${form.name}"...`);
  const res = await request('POST', `${BASE_URL}/api/admin/forms`, form, token);

  if (res.status === 200 || res.status === 201) {
    const created = res.body.form || res.body;
    console.log(`✅ Formulier aangemaakt! ID: ${created.id}`);
    console.log('\n📌 Volgende stap:');
    console.log('   Log in als admin op https://aquaapp2-0.onrender.com');
    console.log('   Ga naar het formulier → wijs monteurs toe die dit formulier mogen zien.');
    console.log('   Als je een klantenlijst hebt, upload die dan onder "Lijsten" en koppel hem aan het veld "Selecteer de servicelocatie".');
  } else {
    console.error('❌ Aanmaken mislukt:', res.status, res.body);
  }
}

run().catch(e => { console.error('❌ Fout:', e.message); process.exit(1); });
