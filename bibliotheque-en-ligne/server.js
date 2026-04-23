const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = 3001;
const SECRET = 'bibliotheque_secret_2025';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ── BASE DE DONNÉES ──
const db = new sqlite3.Database(path.join(__dirname, 'bibliotheque.db'));

const run = (sql, params = []) => new Promise((res, rej) =>
  db.run(sql, params, function(err) { err ? rej(err) : res(this); }));
const get = (sql, params = []) => new Promise((res, rej) =>
  db.get(sql, params, (err, row) => err ? rej(err) : res(row)));
const all = (sql, params = []) => new Promise((res, rej) =>
  db.all(sql, params, (err, rows) => err ? rej(err) : res(rows)));

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prenom TEXT NOT NULL,
    nom TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS Livres (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    titre TEXT NOT NULL,
    auteur TEXT NOT NULL,
    genre TEXT NOT NULL,
    emoji TEXT,
    couleur TEXT,
    disponible INTEGER DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS Emprunts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    livre_id INTEGER NOT NULL,
    date_emprunt TEXT NOT NULL,
    rendu INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES Users(id),
    FOREIGN KEY (livre_id) REFERENCES Livres(id)
  )`);

  // Insérer les livres si la table est vide
  db.get('SELECT COUNT(*) as count FROM Livres', (err, row) => {
    if (row && row.count === 0) {
      const livres = [
        ['Le Comte de Monte-Cristo', 'Alexandre Dumas', 'Roman', '⚔️', '#2d1f0e'],
        ['1984', 'George Orwell', 'Science-Fiction', '👁️', '#0e1a2d'],
        ["L'Étranger", 'Albert Camus', 'Roman', '🌅', '#2d2010'],
        ['Dune', 'Frank Herbert', 'Science-Fiction', '🏜️', '#2d2008'],
        ['Le Nom de la Rose', 'Umberto Eco', 'Policier', '🔍', '#1a1208'],
        ['Sapiens', 'Yuval Noah Harari', 'Histoire', '🦴', '#0e2214'],
        ['Le Petit Prince', "Antoine de Saint-Exupéry", 'Roman', '🌹', '#1a0e2d'],
        ['Fahrenheit 451', 'Ray Bradbury', 'Science-Fiction', '🔥', '#2d0e0e'],
        ['Crime et Châtiment', 'Fiodor Dostoïevski', 'Roman', '🪓', '#1a1a1a'],
        ['Le Meilleur des Mondes', 'Aldous Huxley', 'Science-Fiction', '🧬', '#0e2020'],
        ['Le Silence des Agneaux', 'Thomas Harris', 'Policier', '🐑', '#200e14'],
        ['Steve Jobs', 'Walter Isaacson', 'Biographie', '🍎', '#1a1a2d'],
        ['La République', 'Platon', 'Philosophie', '🏛️', '#2d2214'],
        ['Les Misérables', 'Victor Hugo', 'Roman', '🎭', '#0e1a1a'],
        ['Fondation', 'Isaac Asimov', 'Science-Fiction', '🚀', '#0a0e2d'],
        ['Sherlock Holmes', 'Arthur Conan Doyle', 'Policier', '🔎', '#14200e'],
      ];
      livres.forEach(l => {
        db.run('INSERT INTO Livres (titre, auteur, genre, emoji, couleur) VALUES (?,?,?,?,?)', l);
      });
      console.log('✅ Livres insérés');
    }
  });
});

// ── MIDDLEWARE AUTH ──
function authMiddleware(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non authentifié' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

// ── AUTH ROUTES ──
app.post('/api/register', async (req, res) => {
  const { prenom, nom, email, password } = req.body;
  if (!prenom || !nom || !email || !password)
    return res.status(400).json({ error: 'Tous les champs sont obligatoires' });
  try {
    const existing = await get('SELECT id FROM Users WHERE email = ?', [email]);
    if (existing) return res.status(409).json({ error: 'Un compte existe déjà avec cet email' });
    const hashed = await bcrypt.hash(password, 10);
    const result = await run('INSERT INTO Users (prenom, nom, email, password) VALUES (?,?,?,?)', [prenom, nom, email, hashed]);
    const token = jwt.sign({ id: result.lastID, prenom, nom, email }, SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: result.lastID, prenom, nom, email } });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await get('SELECT * FROM Users WHERE email = ?', [email]);
    if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    const token = jwt.sign({ id: user.id, prenom: user.prenom, nom: user.nom, email: user.email }, SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: user.id, prenom: user.prenom, nom: user.nom, email: user.email } });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Déconnexion réussie' });
});

app.get('/api/me', authMiddleware, (req, res) => res.json({ user: req.user }));

// ── LIVRES ROUTES ──
app.get('/api/livres', async (req, res) => {
  try {
    const livres = await all(`
      SELECT l.*,
        (SELECT COUNT(*) FROM Emprunts e WHERE e.livre_id = l.id AND e.rendu = 0) as nb_emprunts
      FROM Livres l
    `);
    res.json(livres);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ── EMPRUNTS ROUTES ──
app.post('/api/emprunts', authMiddleware, async (req, res) => {
  const { livre_id } = req.body;
  try {
    const emprunt = await get('SELECT id FROM Emprunts WHERE livre_id = ? AND rendu = 0', [livre_id]);
    if (emprunt) return res.status(400).json({ error: 'Ce livre est déjà emprunté' });
    const dejaEmprunte = await get('SELECT id FROM Emprunts WHERE livre_id = ? AND user_id = ? AND rendu = 0', [livre_id, req.user.id]);
    if (dejaEmprunte) return res.status(400).json({ error: 'Vous avez déjà emprunté ce livre' });
    const date = new Date().toLocaleDateString('fr-FR');
    await run('INSERT INTO Emprunts (user_id, livre_id, date_emprunt) VALUES (?,?,?)', [req.user.id, livre_id, date]);
    res.json({ message: 'Emprunt effectué' });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.get('/api/emprunts/mes-emprunts', authMiddleware, async (req, res) => {
  try {
    const emprunts = await all(`
      SELECT e.*, l.titre, l.auteur, l.emoji, l.genre
      FROM Emprunts e JOIN Livres l ON e.livre_id = l.id
      WHERE e.user_id = ? AND e.rendu = 0
      ORDER BY e.date_emprunt DESC
    `, [req.user.id]);
    res.json(emprunts);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.put('/api/emprunts/:id/rendre', authMiddleware, async (req, res) => {
  try {
    const emprunt = await get('SELECT * FROM Emprunts WHERE id = ?', [req.params.id]);
    if (!emprunt) return res.status(404).json({ error: 'Emprunt introuvable' });
    if (emprunt.user_id !== req.user.id) return res.status(403).json({ error: 'Non autorisé' });
    await run('UPDATE Emprunts SET rendu = 1 WHERE id = ?', [req.params.id]);
    res.json({ message: 'Livre rendu' });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

app.listen(PORT, () => console.log(`📚 Bibliothèque démarrée sur http://localhost:${PORT}`));
