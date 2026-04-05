require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { Resend } = require('resend');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const csv = require('csv-parser');
const XLSX = require('xlsx');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'aquaapp-geheim-verander-dit-in-productie';

// ===== SECURITY HEADERS =====
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ===== MIDDLEWARE =====
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('index.html')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// ===== FILE UPLOAD =====
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

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

// Atomic write: schrijf naar .tmp dan rename → geen corruptie bij crash
function writeJSON(file, data) {
  const fullPath = path.join(dataDir, file);
  const tmp = fullPath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  fs.renameSync(tmp, fullPath);
}

// ===== INIT DATA =====
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(listsDir)) fs.mkdirSync(listsDir, { recursive: true });

const testFormId = 'test-form-default-id';
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
      password: bcrypt.hashSync('1', 10),
      name: 'Monteur',
      role: 'monteur',
      allowedForms: [testFormId]
    }
  ]);
  console.log('Standaard gebruikers aangemaakt.');
}
if (!fs.existsSync(path.join(dataDir, 'forms.json'))) {
  writeJSON('forms.json', [{
    id: testFormId,
    name: 'TEST FORM',
    email: 'r.zijlstra@aqua.nl',
    fields: [
      { id: 'f_datum', type: 'date', label: 'Datum', required: true },
      { id: 'f_email', type: 'email', label: 'Email', required: false },
      { id: 'f_foto', type: 'photo', label: 'Foto', required: false }
    ],
    createdAt: new Date().toISOString()
  }]);
  console.log('Standaard TEST FORM aangemaakt.');
}
if (!fs.existsSync(path.join(dataDir, 'lists.json'))) writeJSON('lists.json', []);

// ===== RATE LIMITING (login) =====
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  if (!loginAttempts.has(ip)) loginAttempts.set(ip, []);
  const attempts = loginAttempts.get(ip).filter(t => now - t < 60000); // sliding 60s window
  loginAttempts.set(ip, attempts);
  if (attempts.length >= 10) return false; // max 10 pogingen per minuut
  attempts.push(now);
  return true;
}
// Opruimen van oude rate-limit entries om memory leaks te voorkomen
setInterval(() => {
  const now = Date.now();
  for (const [ip, times] of loginAttempts.entries()) {
    const fresh = times.filter(t => now - t < 60000);
    if (fresh.length === 0) loginAttempts.delete(ip);
    else loginAttempts.set(ip, fresh);
  }
}, 5 * 60 * 1000);

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
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Te veel inlogpogingen. Probeer het over een minuut opnieuw.' });
  }
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

// ===== REGISTRATIE =====
app.post('/api/register', async (req, res) => {
  const { name, email, regio, password } = req.body;
  if (!name || !email || !regio || !password) return res.status(400).json({ error: 'Vul alle velden in' });
  if (password.length < 6) return res.status(400).json({ error: 'Wachtwoord moet minimaal 6 tekens zijn' });
  const users = readJSON('users.json');
  if (users.find(u => u.username === email)) return res.status(400).json({ error: 'Dit e-mailadres is al geregistreerd' });
  const newUser = {
    id: uuidv4(),
    username: email,
    password: bcrypt.hashSync(password, 10),
    name, email, regio,
    role: 'monteur',
    allowedForms: []
  };
  users.push(newUser);
  writeJSON('users.json', users);

  // Stuur notificatiemail naar admin(s)
  if (process.env.RESEND_API_KEY) {
    try {
      const adminUsers = users.filter(u => u.role === 'admin' && (u.email || u.username));
      const adminEmails = adminUsers.map(u => u.email || u.username);
      if (adminEmails.length > 0) {
        const resend = new Resend(process.env.RESEND_API_KEY);
        await resend.emails.send({
          from: 'AquaApp <onboarding@resend.dev>',
          to: adminEmails,
          subject: `Nieuwe monteur geregistreerd: ${name}`,
          text: `Hallo,\n\nEen nieuwe monteur heeft zich geregistreerd:\n\nNaam: ${name}\nE-mail: ${email}\nRegio: ${regio}\n\nLog in op AquaApp om toegang te verlenen tot formulieren.\n\n— AquaApp`
        });
      }
    } catch(e) { console.error('Registratie notificatie fout:', e); }
  }

  const token = jwt.sign(
    { id: newUser.id, username: newUser.username, role: newUser.role, name: newUser.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  res.json({ token, user: { id: newUser.id, username: newUser.username, role: newUser.role, name: newUser.name } });
});

// ===== WACHTWOORD VERGETEN =====
const resetTokens = {}; // { token: { userId, expires } }

app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Vul een e-mailadres in' });
  const users = readJSON('users.json');
  const user = users.find(u => u.username === email || u.email === email);
  // Altijd succes teruggeven (geen enumeration)
  if (!user) return res.json({ ok: true });

  const token = uuidv4();
  resetTokens[token] = { userId: user.id, expires: Date.now() + 1000 * 60 * 60 }; // 1 uur geldig

  const resetUrl = `${req.protocol}://${req.get('host')}/?reset=${token}`;

  try {
    const resend = new Resend(process.env.RESEND_API_KEY);
    await resend.emails.send({
      from: 'AquaApp <noreply@aquaapp.nl>',
      to: user.email || user.username,
      subject: 'Wachtwoord opnieuw instellen – AquaApp',
      text: `Hallo ${user.name},\n\nKlik op de onderstaande link om je wachtwoord opnieuw in te stellen:\n\n${resetUrl}\n\nDeze link is 1 uur geldig.\n\n— AquaApp`
    });
  } catch (e) {
    console.error('Reset mail fout:', e);
  }
  res.json({ ok: true });
});

app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Ongeldig verzoek' });
  if (password.length < 6) return res.status(400).json({ error: 'Wachtwoord moet minimaal 6 tekens zijn' });
  const entry = resetTokens[token];
  if (!entry || Date.now() > entry.expires) return res.status(400).json({ error: 'Link is verlopen of ongeldig' });

  const users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === entry.userId);
  if (idx === -1) return res.status(404).json({ error: 'Gebruiker niet gevonden' });
  users[idx].password = bcrypt.hashSync(password, 10);
  writeJSON('users.json', users);
  delete resetTokens[token];
  res.json({ ok: true });
});

// ===== PROFIEL (monteur zelf) =====
app.put('/api/profile', authMiddleware, upload.single('photo'), (req, res) => {
  const users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === req.user.id);
  if (idx === -1) return res.status(404).json({ error: 'Gebruiker niet gevonden' });
  const { skills, age, title, bio } = req.body;
  users[idx] = {
    ...users[idx],
    ...(skills !== undefined && { skills }),
    ...(age !== undefined && { age }),
    ...(title !== undefined && { title }),
    ...(bio !== undefined && { bio }),
    ...(req.file && { photoUrl: `/uploads/${req.file.filename}` })
  };
  writeJSON('users.json', users);
  const { password: _, ...safeUser } = users[idx];
  res.json(safeUser);
});

// ===== ADMIN - USERS =====
app.get('/api/admin/users', authMiddleware, adminOnly, (req, res) => {
  const users = readJSON('users.json').map(u => { const { password, ...rest } = u; return rest; });
  res.json(users);
});

// Admin wijzigt rol van een gebruiker
app.put('/api/admin/users/:id/role', authMiddleware, adminOnly, (req, res) => {
  const { role } = req.body;
  if (!['admin', 'monteur'].includes(role)) return res.status(400).json({ error: 'Ongeldige rol' });
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Je kunt je eigen rol niet wijzigen' });
  const users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Gebruiker niet gevonden' });
  // Voorkom dat de laatste admin gedegradeerd wordt
  if (role === 'monteur' && users[idx].role === 'admin') {
    const adminCount = users.filter(u => u.role === 'admin').length;
    if (adminCount <= 1) return res.status(400).json({ error: 'Er moet minimaal één beheerder blijven' });
  }
  users[idx].role = role;
  writeJSON('users.json', users);
  const { password: _, ...safeUser } = users[idx];
  res.json(safeUser);
});

// Admin reset wachtwoord van een monteur
app.post('/api/admin/users/:id/reset-password', authMiddleware, adminOnly, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Wachtwoord minimaal 6 tekens' });
  const users = readJSON('users.json');
  const idx = users.findIndex(u => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Gebruiker niet gevonden' });
  users[idx].password = bcrypt.hashSync(password, 10);
  writeJSON('users.json', users);
  res.json({ ok: true });
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
  if (!user) return res.status(404).json({ error: 'Gebruiker niet gevonden' });
  if (user.role === 'admin') {
    const adminCount = users.filter(u => u.role === 'admin').length;
    if (adminCount <= 1) return res.status(400).json({ error: 'Er moet minimaal één beheerder blijven' });
  }
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

// ===== INZENDINGEN =====
if (!fs.existsSync(path.join(dataDir, 'submissions.json'))) writeJSON('submissions.json', []);

app.get('/api/submissions', authMiddleware, (req, res) => {
  const submissions = readJSON('submissions.json');
  if (req.user.role === 'admin') return res.json(submissions);
  res.json(submissions.filter(s => s.userId === req.user.id));
});

// Admin: status van een inzending wijzigen
app.put('/api/admin/submissions/:id/status', authMiddleware, adminOnly, (req, res) => {
  const { status } = req.body;
  const validStatuses = ['nieuw', 'in-behandeling', 'verwerkt'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Ongeldige status' });
  const submissions = readJSON('submissions.json');
  const idx = submissions.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Inzending niet gevonden' });
  submissions[idx].status = status;
  submissions[idx].statusUpdatedAt = new Date().toISOString();
  writeJSON('submissions.json', submissions);
  res.json(submissions[idx]);
});

// Admin: CSV-export van alle inzendingen
app.get('/api/admin/submissions/export', authMiddleware, adminOnly, (req, res) => {
  const submissions = readJSON('submissions.json');
  const forms = readJSON('forms.json');

  const rows = [['ID', 'Formulier', 'Monteur', 'Datum', 'Tijd', 'Status', "Foto's", 'Handtekening']];
  for (const sub of submissions) {
    const d = new Date(sub.submittedAt);
    const datum = d.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const tijd  = d.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });

    // Basisrijen
    rows.push([
      sub.id,
      sub.formName || '—',
      sub.userName || '—',
      datum,
      tijd,
      sub.status || 'nieuw',
      sub.photoCount || 0,
      sub.hasSignature ? 'Ja' : 'Nee'
    ]);

    // Veldwaarden toevoegen als extra kolommen (eerste rij als koptekst)
    const form = forms.find(f => f.id === sub.formId);
    if (form && sub.data) {
      for (const field of (form.fields || [])) {
        if (['photo', 'signature', 'heading', 'divider'].includes(field.type)) continue;
        const val = sub.data[field.id];
        const display = Array.isArray(val) ? val.join('; ') : (val !== undefined && val !== null ? String(val) : '');
        rows[rows.length - 1].push(display);
        // Koptekst voor eerste sub uitbreiden (vereenvoudigd: niet ideaal voor meerdere formulieren)
      }
    }
  }

  const csvContent = rows.map(r =>
    r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')
  ).join('\r\n');

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="inzendingen-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send('\uFEFF' + csvContent); // BOM zodat Excel UTF-8 herkent
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

    if (process.env.RESEND_API_KEY && form.email) {
      try {
        await sendEmail(form, formData, photos, signature, req.user);
      } catch (emailErr) {
        console.error('E-mail verzenden mislukt (inzending wél opgeslagen):', emailErr.message);
      }
    }

    // Inzending opslaan — foto's bewaren zodat admin ze kan bekijken
    const photoUrls = photos.map(p => `/uploads/${path.basename(p.path)}`);
    const submissions = readJSON('submissions.json');
    submissions.push({
      id: uuidv4(),
      formId: form.id,
      formName: form.name,
      userId: req.user.id,
      userName: req.user.name,
      data: formData,
      photoCount: photos.length,
      photoUrls,
      hasSignature: !!signature,
      status: 'nieuw',
      submittedAt: new Date().toISOString()
    });
    writeJSON('submissions.json', submissions);

    res.json({ success: true, message: 'Formulier succesvol verzonden!' });
  } catch (err) {
    photoPaths.forEach(p => { if (fs.existsSync(p)) fs.unlinkSync(p); });
    console.error('Submit error:', err);
    res.status(500).json({ error: 'Fout bij verzenden: ' + err.message });
  }
});

// ===== EMAIL VERZENDING =====
async function sendEmail(form, formData, photos, signature, user) {
  if (!process.env.RESEND_API_KEY) return;
  if (!form.email) return;

  const resend = new Resend(process.env.RESEND_API_KEY);

  const now = new Date();
  const datumStr = now.toLocaleDateString('nl-NL', { day: '2-digit', month: '2-digit', year: 'numeric' });
  const tijdStr = now.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });

  let text = `AquaApp - Formulier Inzending\n${'═'.repeat(45)}\n`;
  text += `Formulier : ${form.name}\n`;
  text += `Monteur   : ${user.name}\n`;
  text += `Datum     : ${datumStr} om ${tijdStr}\n`;
  text += `${'═'.repeat(45)}\n\n`;

  function isFieldVisible(field) {
    if (field.type === 'divider' || field.type === 'heading') return true;
    const conditions = (form.conditions) || [];
    const relevantConds = conditions.filter(c => c.thenFieldId === field.id && c.ifFieldId);
    if (relevantConds.length === 0) return true;
    return relevantConds.some(c => {
      const val = formData[c.ifFieldId];
      const actual = (val === undefined || val === null) ? '' : String(val).toLowerCase();
      const cVal = (c.value || '').toLowerCase();
      switch (c.operator) {
        case 'equals':     return actual === cVal;
        case 'not_equals': return actual !== cVal;
        case 'contains':   return actual.includes(cVal);
        case 'not_empty':  return actual !== '';
        case 'empty':      return actual === '';
        default: return true;
      }
    });
  }

  for (const field of (form.fields || [])) {
    if (['signature','photo','heading','divider'].includes(field.type)) continue;
    if (!isFieldVisible(field)) continue;
    const val = formData[field.id];
    let displayVal = '—';
    if (field.type === 'checkbox' && Array.isArray(val)) displayVal = val.join(', ') || '—';
    else if (val !== undefined && val !== null && val !== '') displayVal = String(val);
    text += `${field.label.split('\n')[0]}: ${displayVal}\n`;
  }
  text += `\n— Verzonden via AquaApp\n`;

  const attachments = [];
  for (let i = 0; i < photos.length; i++) {
    const p = photos[i];
    const content = fs.readFileSync(p.path).toString('base64');
    const ext = path.extname(p.originalname || p.path) || '.jpg';
    attachments.push({ filename: `foto_${i + 1}${ext}`, content });
  }

  if (signature && signature.startsWith('data:image')) {
    const base64Data = signature.replace(/^data:image\/\w+;base64,/, '');
    attachments.push({ filename: 'handtekening.png', content: base64Data });
  }

  const recipients = (form.email || '').split(',').map(e => e.trim()).filter(Boolean);
  const { error } = await resend.emails.send({
    from: 'AquaApp <onboarding@resend.dev>',
    to: recipients.length > 0 ? recipients : [form.email],
    subject: `[AquaApp] ${form.name} — ${user.name} — ${datumStr}`,
    text,
    attachments
  });

  if (error) throw new Error(error.message);
}

// ===== SPA FALLBACK =====
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ===== START =====
app.listen(PORT, () => console.log(`AquaApp draait op http://localhost:${PORT}`));
