require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const csv = require('csv-parser');
const XLSX = require('xlsx');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'aquaapp-geheim-verander-dit-in-productie';

// ===== MIDDLEWARE =====
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== FILE UPLOAD =====
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${file.originalname}`)
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });

// ===== DATA HELPERS =====
const dataDir = path.join(__dirname, 'data');
const listsDir = path.join(dataDir, 'lists');

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(path.join(dataDir, file), 'utf8')); }
  catch { return []; }
}
function writeJSON(file, data) {
  fs.writeFileSync(path.join(dataDir, file), JSON.stringify(data, null, 2));
}

// ===== INIT DATA =====
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(listsDir)) fs.mkdirSync(listsDir, { recursive: true });

if (!fs.existsSync(path.join(dataDir, 'users.json'))) {
  writeJSON('users.json', [{
    id: uuidv4(),
    username: 'admin',
    password: bcrypt.hashSync('admin123', 10),
    name: 'Beheerder',
    role: 'admin',
    allowedForms: []
  }]);
  console.log('Standaard admin aangemaakt: gebruikersnaam=admin, wachtwoord=admin123');
}
if (!fs.existsSync(path.join(dataDir, 'forms.json'))) writeJSON('forms.json', []);
if (!fs.existsSync(path.join(dataDir, 'lists.json'))) writeJSON('lists.json', []);

// ===== AUTH MIDDLEWARE =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Niet ingelogd' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Sessie verlopen, log opnieuw in' });
  }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Alleen beheerders hebben toegang' });
  next();
}

// ===== AUTH ROUTES =====
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Vul gebruikersnaam en wachtwoord in' });
  const users = readJSON('users.json');
  const user = users.find(u => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Onjuiste gebruikersnaam of wachtwoord' });
  }
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, user: { id: user.id, username: user.username, role: user.role, name: user.name } });
});

app.get('/api/me', authMiddleware, (req, res) => res.json(req.user));

// ===== ADMIN - USERS =====
app.get('/api/admin/users', authMiddleware, adminOnly, (req, res) => {
  const users = readJSON('users.json').map(u => { const { password, ...rest } = u; return rest; });
  res.json(users);
});

app.post('/api/admin/users', authMiddleware, adminOnly, (req, res) => {
  const { username, password, name, role, allowedForms } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: 'Vul alle verplichte velden in' });
  const users = readJSON('users.json');
  if (users.find(u => u.username === username)) return res.status(400).json({ error: 'Gebruikersnaam bestaat al' });
  const newUser = {
    id: uuidv4(), username, password: bcrypt.hashSync(password, 10),
    name, role: role || 'monteur', allowedForms: allowedForms || []
  };
  users.push(newUser);
  writeJSON('users.json', users);
  const { password: _, ...safeUser } = newUser;
  res.json(safeUser);
});

app.put('/api/admin/users/:id', authMiddleware, adminOnly, (req, res) => {
  const { username, password, name, role, allowedForms } = req.body;
  let users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Gebruiker niet gevonden' });
  if (username && username !== users[idx].username && users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Gebruikersnaam bestaat al' });
  }
  users[idx] = {
    ...users[idx],
    ...(username && { username }),
    ...(name && { name }),
    ...(role && { role }),
    ...(allowedForms !== undefined && { allowedForms }),
    ...(password && { password: bcrypt.hashSync(password, 10) })
  };
  writeJSON('users.json', users);
  const { password: _, ...safeUser } = users[idx];
  res.json(safeUser);
});

app.delete('/api/admin/users/:id', authMiddleware, adminOnly, (req, res) => {
  const users = readJSON('users.json');
  const user = users.find(u => u.id === req.params.id);
  if (user?.role === 'admin') return res.status(400).json({ error: 'Kan de beheerder niet verwijderen' });
  writeJSON('users.json', users.filter(u => u.id !== req.params.id));
  res.json({ success: true });
});

// ===== ADMIN - FORMS =====
app.get('/api/admin/forms', authMiddleware, adminOnly, (req, res) => res.json(readJSON('forms.json')));

app.post('/api/admin/forms', authMiddleware, adminOnly, (req, res) => {
  if (!req.body.name) return res.status(400).json({ error: 'Formuliernaam is verplicht' });
  const forms = readJSON('forms.json');
  const newForm = { id: uuidv4(), ...req.body, createdAt: new Date().toISOString() };
  forms.push(newForm);
  writeJSON('forms.json', forms);
  res.json(newForm);
});

app.put('/api/admin/forms/:id', authMiddleware, adminOnly, (req, res) => {
  let forms = readJSON('forms.json');
  const idx = forms.findIndex(f => f.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Formulier niet gevonden' });
  forms[idx] = { ...forms[idx], ...req.body, id: req.params.id };
  writeJSON('forms.json', forms);
  res.json(forms[idx]);
});

app.delete('/api/admin/forms/:id', authMiddleware, adminOnly, (req, res) => {
  writeJSON('forms.json', readJSON('forms.json').filter(f => f.id !== req.params.id));
  res.json({ success: true });
});

// ===== ADMIN - LISTS =====
app.get('/api/admin/lists', authMiddleware, adminOnly, (req, res) => res.json(readJSON('lists.json')));

app.post('/api/admin/lists/upload', authMiddleware, adminOnly, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Geen bestand ontvangen' });
  const listName = req.body.name || path.basename(req.file.originalname, path.extname(req.file.originalname));
  const ext = path.extname(req.file.originalname).toLowerCase();
  let items = [];

  try {
    if (ext === '.csv') {
      await new Promise((resolve, reject) => {
        fs.createReadStream(req.file.path)
          .pipe(csv({ headers: false }))
          .on('data', row => {
            const val = Object.values(row)[0];
            if (val && String(val).trim()) items.push(String(val).trim());
          })
          .on('end', resolve).on('error', reject);
      });
    } else if (['.xlsx', '.xls'].includes(ext)) {
      const wb = XLSX.readFile(req.file.path);
      const ws = wb.Sheets[wb.SheetNames[0]];
      const rows = XLSX.utils.sheet_to_json(ws, { header: 1 });
      items = rows.map(r => r[0]).filter(v => v !== undefined && v !== '').map(String).map(s => s.trim());
    } else {
      items = fs.readFileSync(req.file.path, 'utf8').split('\n').map(l => l.trim()).filter(l => l);
    }

    if (items.length === 0) return res.status(400).json({ error: 'Geen geldige items gevonden in het bestand' });

    const listId = uuidv4();
    const listFile = `${listId}.json`;
    fs.writeFileSync(path.join(listsDir, listFile), JSON.stringify(items, null, 2));

    const lists = readJSON('lists.json');
    const newList = { id: listId, name: listName, file: listFile, count: items.length, uploadedAt: new Date().toISOString() };
    lists.push(newList);
    writeJSON('lists.json', lists);

    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.json(newList);
  } catch (err) {
    if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(500).json({ error: 'Fout bij verwerken: ' + err.message });
  }
});

app.put('/api/admin/lists/:id', authMiddleware, adminOnly, (req, res) => {
  const lists = readJSON('lists.json');
  const idx = lists.findIndex(l => l.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Lijst niet gevonden' });
  if (req.body.name) lists[idx].name = req.body.name;
  writeJSON('lists.json', lists);
  res.json(lists[idx]);
});

app.delete('/api/admin/lists/:id', authMiddleware, adminOnly, (req, res) => {
  const lists = readJSON('lists.json');
  const list = lists.find(l => l.id === req.params.id);
  if (list) {
    const fp = path.join(listsDir, list.file);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  }
  writeJSON('lists.json', lists.filter(l => l.id !== req.params.id));
  res.json({ success: true });
});

// ===== MONTEUR - FORMS & LISTS =====
app.get('/api/forms', authMiddleware, (req, res) => {
  const forms = readJSON('forms.json');
  if (req.user.role === 'admin') return res.json(forms);
  const users = readJSON('users.json');
  const user = users.find(u => u.id === req.user.id);
  const allowed = user?.allowedForms || [];
  res.json(forms.filter(f => allowed.includes(f.id)));
});

app.get('/api/lists', authMiddleware, (req, res) => res.json(readJSON('lists.json')));

app.get('/api/lists/:id/items', authMiddleware, (req, res) => {
  const list = readJSON('lists.json').find(l => l.id === req.params.id);
  if (!list) return res.status(404).json({ error: 'Lijst niet gevonden' });
  try {
    const items = JSON.parse(fs.readFileSync(path.join(listsDir, list.file), 'utf8'));
    res.json({ ...list, items });
  } catch {
    res.status(500).json({ error: 'Fout bij laden lijst' });
  }
});

// ===== FORM SUBMISSION =====
app.post('/api/submit/:formId', authMiddleware, upload.fields([{ name: 'photos', maxCount: 20 }]), async (req, res) => {
  const photoPaths = [];
  try {
    const form = readJSON('forms.json').find(f => f.id === req.params.formId);
    if (!form) return res.status(404).json({ error: 'Formulier niet gevonden' });

    const formData = JSON.parse(req.body.data || '{}');
    const signature = req.body.signature || null;
    const photos = req.files?.photos || [];
    photos.forEach(p => photoPaths.push(p.path));

    const pdfBuffer = await generatePDF(form, formData, photos, signature, req.user);
    await sendEmail(form, formData, pdfBuffer, req.user);

    photos.forEach(p => { if (fs.existsSync(p.path)) fs.unlinkSync(p.path); });
    res.json({ success: true, message: 'Formulier succesvol verzonden!' });
  } catch (err) {
    photoPaths.forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });
    console.error('Submit error:', err);
    res.status(500).json({ error: 'Fout bij verzenden: ' + err.message });
  }
});

// ===== PDF GENERATIE =====
async function generatePDF(form, formData, photos, signature, user) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4', bufferPages: true });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    const BLUE = '#0057B8';
    const GREY = '#9BA3AE';
    const DARK = '#1C2833';
    const LIGHT = '#F5F8FC';
    const W = doc.page.width;

    // Header blok
    doc.rect(0, 0, W, 90).fill(BLUE);
    doc.fillColor('white').font('Helvetica-Bold').fontSize(28).text('aqua+', 50, 22);
    doc.fontSize(11).font('Helvetica').text(form.name, 50, 56);
    doc.fillColor(GREY).fontSize(9).text('www.aquaplus.nl', W - 150, 56, { width: 100, align: 'right' });

    // Meta info
    const now = new Date();
    const datumStr = now.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const tijdStr = now.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });

    doc.y = 110;
    doc.rect(50, doc.y, W - 100, 45).fill(LIGHT);
    doc.fillColor(DARK).font('Helvetica').fontSize(9);
    doc.text(`Monteur: ${user.name}`, 60, doc.y + 8);
    doc.text(`Datum: ${datumStr}  |  Tijd: ${tijdStr}`, 60, doc.y + 8 + 14);
    doc.y += 55 + 14;

    // Scheidingslijn
    doc.moveTo(50, doc.y).lineTo(W - 50, doc.y).strokeColor(BLUE).lineWidth(2).stroke();
    doc.moveDown(0.8);

    // Velden
    for (const field of (form.fields || [])) {
      if (field.type === 'signature' || field.type === 'photo') continue;

      const val = formData[field.id];
      let displayVal = '—';

      if (field.type === 'checkbox' && Array.isArray(val)) {
        displayVal = val.length > 0 ? val.join(', ') : '—';
      } else if (val !== undefined && val !== null && val !== '') {
        displayVal = String(val);
      }

      if (doc.y > doc.page.height - 100) doc.addPage();

      doc.font('Helvetica-Bold').fontSize(9).fillColor(BLUE).text(field.label.toUpperCase(), 50, doc.y, { width: W - 100 });
      doc.font('Helvetica').fontSize(10).fillColor(DARK).text(displayVal, 50, doc.y + 2, { width: W - 100, indent: 0 });
      doc.moveDown(0.6);
      doc.moveTo(50, doc.y).lineTo(W - 50, doc.y).strokeColor('#E8EEF5').lineWidth(0.5).stroke();
      doc.moveDown(0.4);
    }

    // Handtekening
    if (signature && signature.startsWith('data:image')) {
      if (doc.y > doc.page.height - 150) doc.addPage();
      doc.moveDown(0.5);
      doc.font('Helvetica-Bold').fontSize(9).fillColor(BLUE).text('HANDTEKENING', 50);
      doc.moveDown(0.3);
      try {
        const base64 = signature.replace(/^data:image\/\w+;base64,/, '');
        const buf = Buffer.from(base64, 'base64');
        doc.rect(50, doc.y, 220, 85).strokeColor('#D0D8E4').lineWidth(1).stroke();
        doc.image(buf, 52, doc.y + 2, { width: 216, height: 81 });
        doc.y += 95;
      } catch {
        doc.font('Helvetica').fillColor(DARK).text('(Handtekening kon niet worden weergegeven)');
      }
    }

    // Foto's
    if (photos.length > 0) {
      if (doc.y > doc.page.height - 220) doc.addPage();
      doc.moveDown(0.5);
      doc.font('Helvetica-Bold').fontSize(9).fillColor(BLUE).text("FOTO'S", 50);
      doc.moveDown(0.4);

      const imgW = 240, imgH = 180, gap = 15;
      let col = 0, startY = doc.y;

      for (let i = 0; i < photos.length; i++) {
        const x = 50 + col * (imgW + gap);
        if (startY + imgH > doc.page.height - 50) { doc.addPage(); startY = 50; col = 0; }
        try {
          doc.rect(x, startY, imgW, imgH).strokeColor('#D0D8E4').lineWidth(1).stroke();
          doc.image(photos[i].path, x + 2, startY + 2, { width: imgW - 4, height: imgH - 4, fit: [imgW - 4, imgH - 4], align: 'center', valign: 'center' });
        } catch { /* skip */ }
        col++;
        if (col >= 2) { col = 0; startY += imgH + gap; }
      }
      doc.y = startY + (col > 0 ? imgH + gap : 0);
    }

    // Paginanummers
    const range = doc.bufferedPageRange();
    for (let i = 0; i < range.count; i++) {
      doc.switchToPage(i);
      doc.fontSize(8).fillColor(GREY).text(
        `AquaApp  ·  ${form.name}  ·  Pagina ${i + 1} van ${range.count}`,
        50, doc.page.height - 30, { width: W - 100, align: 'center' }
      );
    }

    doc.end();
  });
}

// ===== EMAIL VERZENDING =====
async function sendEmail(form, formData, pdfBuffer, user) {
  if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
    throw new Error('SMTP niet geconfigureerd. Stel SMTP_USER en SMTP_PASS in als omgevingsvariabelen.');
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });

  const now = new Date();
  const datumStr = now.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit', year: 'numeric' });
  const tijdStr = now.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });

  let text = `AquaApp - Formulier Inzending\n${'═'.repeat(45)}\n`;
  text += `Formulier : ${form.name}\n`;
  text += `Monteur   : ${user.name}\n`;
  text += `Datum     : ${datumStr} om ${tijdStr}\n`;
  text += `${'═'.repeat(45)}\n\n`;

  for (const field of (form.fields || [])) {
    if (field.type === 'signature' || field.type === 'photo') continue;
    const val = formData[field.id];
    let displayVal = '—';
    if (field.type === 'checkbox' && Array.isArray(val)) displayVal = val.join(', ') || '—';
    else if (val !== undefined && val !== null && val !== '') displayVal = String(val);
    text += `${field.label}: ${displayVal}\n`;
  }
  text += `\n— Verzonden via AquaApp\n`;

  const safeFormName = form.name.replace(/[^a-z0-9\s]/gi, '').trim().replace(/\s+/g, '_');
  const safeDatum = now.toISOString().split('T')[0];

  await transporter.sendMail({
    from: `"AquaApp" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
    to: form.email,
    subject: `[AquaApp] ${form.name} — ${user.name} — ${datumStr}`,
    text,
    attachments: [{
      filename: `${safeFormName}_${safeDatum}_${user.name.replace(/\s+/g, '_')}.pdf`,
      content: pdfBuffer,
      contentType: 'application/pdf'
    }]
  });
}

// ===== SPA FALLBACK =====
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ===== START =====
app.listen(PORT, () => console.log(`AquaApp draait op http://localhost:${PORT}`));
