// ===============================
// Carrega variáveis de ambiente
// ===============================
require("dotenv").config();

// ===============================
// Imports
// ===============================
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

// ===============================
// App
// ===============================
const app = express();

// ===============================
// CORS – deixa só seus domínios
// ===============================
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://find-my-song.vercel.app",
      "https://find-my-song-frontend.vercel.app",
      "https://findmysong-frontend.vercel.app",
    ],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// aceita JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// log simples
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ===============================
// Banco (Render Postgres)
// ===============================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false },
});

// health
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ===============================
// Auth (cadastro / login)
// ===============================

// POST /api/usuarios/register
app.post("/api/usuarios/register", async (req, res) => {
  const { nome, email, senha } = req.body;

  if (!nome || !email || !senha) {
    return res.status(400).json({ message: "Preencha todos os campos." });
  }

  try {
    const senhaHash = await bcrypt.hash(senha, 10);

    const result = await pool.query(
      "INSERT INTO usuarios (nome, email, senha) VALUES ($1,$2,$3) RETURNING id, nome, email",
      [nome, email, senhaHash]
    );

    return res
      .status(201)
      .json({ message: "Usuário criado com sucesso!", usuario: result.rows[0] });
  } catch (err) {
    console.error("Erro ao criar usuário:", err);
    return res.status(500).json({ message: "Erro no servidor." });
  }
});

// POST /api/usuarios/login
app.post("/api/usuarios/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ message: "Preencha email e senha." });
  }

  try {
    console.log(`[LOGIN] Tentando login: ${email}`);

    const result = await pool.query(
      "SELECT * FROM usuarios WHERE LOWER(email) = LOWER($1)",
      [email]
    );

    if (result.rows.length === 0) {
      console.log(`[LOGIN] Usuário não encontrado: ${email}`);
      return res.status(401).json({ message: "Usuário não encontrado." });
    }

    const user = result.rows[0];

    const senhaCorreta = await bcrypt.compare(senha, user.senha);
    if (!senhaCorreta) {
      console.log(`[LOGIN] Senha incorreta para ${email}`);
      return res.status(401).json({ message: "Senha incorreta." });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || "segredo123",
      { expiresIn: "7d" }
    );

    console.log(`[LOGIN] Login bem-sucedido: ${email}`);
    return res.json({ message: "Login bem-sucedido!", token });
  } catch (err) {
    console.error("[LOGIN] Erro inesperado:", err);
    return res.status(500).json({ message: "Erro no servidor." });
  }
});

// rota protegida
app.get("/api/usuarios/me", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace("Bearer ", "");
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const result = await pool.query(
      "SELECT id, nome, email FROM usuarios WHERE id = $1",
      [payload.id]
    );

    return res.json(result.rows[0]);
  } catch {
    return res.status(401).json({ message: "Não autorizado." });
  }
});

// ===============================
// Spotify – com cache
// ===============================
let cachedSpotifyToken = null;
let spotifyExpiresAt = 0;

async function getSpotifyToken() {
  const now = Date.now();
  if (cachedSpotifyToken && now < spotifyExpiresAt - 5000) {
    return cachedSpotifyToken;
  }

  const clientId = process.env.SPOTIFY_CLIENT_ID;
  const clientSecret = process.env.SPOTIFY_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error("SPOTIFY_CLIENT_ID / SECRET não configurados");
  }

  const authHeader =
    "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  const resp = await axios.post(
    "https://accounts.spotify.com/api/token",
    new URLSearchParams({ grant_type: "client_credentials" }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: authHeader,
      },
      timeout: 8000,
    }
  );

  if (!resp.data?.access_token) {
    throw new Error("Spotify não devolveu token");
  }

  cachedSpotifyToken = resp.data.access_token;
  spotifyExpiresAt = now + resp.data.expires_in * 1000;

  console.log("[SPOTIFY] Token gerado. Expira em", resp.data.expires_in, "s");
  return cachedSpotifyToken;
}

// GET /api/spotify/search?q=...
app.get("/api/spotify/search", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório." });

    const token = await getSpotifyToken();

    const r = await axios.get("https://api.spotify.com/v1/search", {
      headers: { Authorization: `Bearer ${token}` },
      params: { q, type: "track", limit: 20 },
      timeout: 8000,
    });

    return res.json(r.data.tracks.items);
  } catch (err) {
    console.error("[SPOTIFY] Erro na busca:", err.response?.data || err.message);
    return res.status(500).json({ message: "Erro na busca Spotify." });
  }
});

// ===============================
// Genius + Spotify – busca por letra
// ===============================
const GENIUS_ACCESS_TOKEN = process.env.GENIUS_ACCESS_TOKEN;
const GENIUS_BASE_URL = "https://api.genius.com";

// GET /api/search-lyrics?q=...
app.get("/api/search-lyrics", async (req, res) => {
  const q = String(req.query.q || "").trim();

  if (!q) {
    return res.status(400).json({ message: "Parâmetro q é obrigatório." });
  }

  if (!GENIUS_ACCESS_TOKEN) {
    console.error("[GENIUS] token não configurado");
    return res.status(500).json({ message: "Chave do Genius não configurada." });
  }

  try {
    // 1) busca no Genius (forçando o termo de letra)
    const geniusResp = await axios.get(`${GENIUS_BASE_URL}/search`, {
      params: { q: `${q} lyrics` },
      headers: { Authorization: `Bearer ${GENIUS_ACCESS_TOKEN}` },
      timeout: 7000, // não deixa o Render ficar esperando pra sempre
    });

    const hits = (geniusResp.data.response?.hits || []).slice(0, 6);

    const results = [];

    // 2) pra cada resultado do Genius, tenta achar no Spotify
    for (const hit of hits) {
      const song = hit.result;
      const title = song.title;
      const artist = song.primary_artist?.name;
      const geniusUrl = song.url;

      // obj base (se o Spotify falhar, pelo menos isso volta)
      const base = {
        title,
        artist,
        genius_url: geniusUrl,
        spotify_url: null,
        preview_url: null,
        image: null,
      };

      try {
        const spToken = await getSpotifyToken();
        const spResp = await axios.get("https://api.spotify.com/v1/search", {
          headers: { Authorization: `Bearer ${spToken}` },
          params: { q: `${title} ${artist}`, type: "track", limit: 1 },
          timeout: 5000,
        });

        const track = spResp.data.tracks.items[0];

        results.push({
          ...base,
          spotify_url: track?.external_urls?.spotify || null,
          preview_url: track?.preview_url || null,
          image: track?.album?.images?.[0]?.url || null,
        });
      } catch (err) {
        // se o Spotify falhar, adiciona mesmo assim
        console.warn("[GENIUS->SPOTIFY] Falhou pra", title, err.message);
        results.push(base);
      }
    }

    return res.json(results);
  } catch (err) {
    console.error("[GENIUS] erro search-lyrics:", err.response?.data || err.message);
    // aqui é onde dava 502 — agora devolve algo
    return res.status(200).json([]);
  }
});

// ===============================
// Rota raiz
// ===============================
app.get("/", (req, res) => {
  res.send("FindMySong backend rodando 🎵");
});

// ===============================
// Sobe servidor
// ===============================
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Servidor rodando na porta ${port}`);
});
