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
  writeJSON('users.json', [
    {
      id: uuidv4(),
      username: 'admin',
      password: bcrypt.hashSync('admin123', 10),
      name: 'Beheerder',
      role: 'admin',
      allowedForms: []
    },
    {
      id: uuidv4(),
      username: 'Monteur',
      password: bcrypt.hashSync('Monteur', 10),
      name: 'Monteur',
      role: 'monteur',
      allowedForms: []
    }
  ]);
  console.log('Standaard gebruikers aangemaakt.');
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

    await sendEmail(form, formData, photos, signature, req.user);

    photos.forEach(p => { if (fs.existsSync(p.path)) fs.unlinkSync(p.path); });
    res.json({ success: true, message: 'Formulier succesvol verzonden!' });
  } catch (err) {
    photoPaths.forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });
    console.error('Submit error:', err);
    res.status(500).json({ error: 'Fout bij verzenden: ' + err.message });
  }
});

// ===== EMAIL VERZENDING =====
async function sendEmail(form, formData, photos, signature, user) {
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

  // Foto's als bijlage
  const attachments = photos.map((p, i) => ({
    filename: `foto_${i + 1}${path.extname(p.originalname || p.path) || '.jpg'}`,
    path: p.path,
    contentType: p.mimetype || 'image/jpeg'
  }));

  // Handtekening als bijlage
  if (signature && signature.startsWith('data:image')) {
    const base64Data = signature.replace(/^data:image\/\w+;base64,/, '');
    attachments.push({
      filename: 'handtekening.png',
      content: Buffer.from(base64Data, 'base64'),
      contentType: 'image/png'
    });
  }

  await transporter.sendMail({
    from: `"AquaApp" <${process.env.SMTP_FROM || process.env.SMTP_USER}>`,
    to: form.email,
    subject: `[AquaApp] ${form.name} — ${user.name} — ${datumStr}`,
    text,
    attachments
  });
}

// ===== SPA FALLBACK =====
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ===== START =====
app.listen(PORT, () => console.log(`AquaApp draait op http://localhost:${PORT}`));
