require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();

// CORS – ajuste depois com o domínio da Vercel
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://SEU-APP.vercel.app" // troque depois pelo seu domínio real
    ],
  })
);

app.use(express.json());

// DB
const { Pool } = require("pg");
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("sslmode=require")
    ? { rejectUnauthorized: false }
    : false,
});

// Teste de saúde
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// --- ROTAS USUÁRIOS ---
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// criar usuário
app.post("/api/usuarios/register", async (req, res) => {
  const { nome, email, senha } = req.body;
  if (!nome || !email || !senha) return res.status(400).json({ message: "Preencha todos os campos" });

  try {
    const hash = await bcrypt.hash(senha, 10);
    const r = await pool.query(
      "INSERT INTO usuarios (nome, email, senha) VALUES ($1,$2,$3) RETURNING id, nome, email",
      [nome, email, hash]
    );
    res.status(201).json({ message: "Usuário criado com sucesso!", usuario: r.rows[0] });
  } catch (err) {
    console.error("Erro ao criar usuário:", err);
    res.status(500).json({ message: "Erro no servidor" });
  }
});

// login
app.post("/api/usuarios/login", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha) return res.status(400).json({ message: "Preencha email e senha" });

  try {
    const r = await pool.query("SELECT * FROM usuarios WHERE email = $1", [email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ message: "Credenciais inválidas" });

    const ok = await bcrypt.compare(senha, user.senha);
    if (!ok) return res.status(401).json({ message: "Credenciais inválidas" });

    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });
    res.json({ message: "Login bem-sucedido!", token });
  } catch (err) {
    console.error("Erro no login:", err);
    res.status(500).json({ message: "Erro no servidor" });
  }
});

// rota protegida simples
app.get("/api/usuarios/me", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace("Bearer ", "");
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const r = await pool.query("SELECT id, nome, email FROM usuarios WHERE id = $1", [payload.id]);
    res.json(r.rows[0]);
  } catch {
    res.status(401).json({ message: "Não autorizado" });
  }
});

// --- ROTAS SPOTIFY (token automático no backend) ---
const axios = require("axios");
let cachedToken = null;
let tokenExpiresAt = 0;

async function getSpotifyToken() {
  const now = Date.now();
  if (cachedToken && now < tokenExpiresAt) return cachedToken;

  const clientId = process.env.SPOTIFY_CLIENT_ID;
  const clientSecret = process.env.SPOTIFY_CLIENT_SECRET;

  const resp = await axios.post(
    "https://accounts.spotify.com/api/token",
    new URLSearchParams({ grant_type: "client_credentials" }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64"),
      },
    }
  );

  cachedToken = resp.data.access_token;
  tokenExpiresAt = now + (resp.data.expires_in - 60) * 1000;
  return cachedToken;
}

// GET /api/spotify/search?q=love
app.get("/api/spotify/search", async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório" });

    const token = await getSpotifyToken();
    const r = await axios.get("https://api.spotify.com/v1/search", {
      headers: { Authorization: `Bearer ${token}` },
      params: { q, type: "track", limit: 20 },
    });

    res.json(r.data.tracks.items);
  } catch (err) {
    console.error("Erro Spotify:", err.response?.data || err.message);
    res.status(500).json({ message: "Erro Spotify" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Backend rodando em http://localhost:${port}`);
});
