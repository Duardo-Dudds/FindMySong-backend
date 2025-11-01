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
// CORS – apenas domínios autorizados
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

// ===============================
// Configuração base
// ===============================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Log básico das requisições
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ===============================
// Banco de Dados (Render PostgreSQL)
// ===============================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false },
});

// Teste de saúde do servidor
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ===============================
// Autenticação (cadastro / login)
// ===============================

// POST /api/usuarios/register – cria novo usuário
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

// POST /api/usuarios/login – autenticação de usuário
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

// GET /api/usuarios/me – rota protegida
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
// Spotify API – token com cache
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
// Genius + Spotify – busca por letra otimizada com filtro de relevância
// ===============================
const GENIUS_ACCESS_TOKEN = process.env.GENIUS_ACCESS_TOKEN;
const GENIUS_BASE_URL = "https://api.genius.com";

app.get("/api/search-lyrics", async (req, res) => {
  const q = String(req.query.q || "").trim();

  if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório." });
  if (!GENIUS_ACCESS_TOKEN)
    return res.status(500).json({ message: "Chave do Genius não configurada." });

  try {
    // Busca no Genius — força o termo de letra e aumenta o limite
    const geniusResp = await axios.get(`${GENIUS_BASE_URL}/search`, {
      params: { q: `${q} lyrics song` },
      headers: { Authorization: `Bearer ${GENIUS_ACCESS_TOKEN}` },
      timeout: 9000,
    });

    const allHits = geniusResp.data.response?.hits || [];

    // Filtra resultados que realmente contêm o termo no título ou artista
    const hits = allHits
      .filter((h) => {
        const title = h.result.title.toLowerCase();
        const artist = h.result.primary_artist?.name?.toLowerCase() || "";
        const search = q.toLowerCase();
        return title.includes(search) || artist.includes(search);
      })
      .slice(0, 25);

    const results = [];

    // Se a busca estiver em português, tenta dar prioridade a faixas com título PT
    const isPortuguese = /[áàãâéêíóôõúç]/i.test(q);

    for (const hit of hits) {
      const song = hit.result;
      const title = song.title;
      const artist = song.primary_artist?.name;
      const geniusUrl = song.url;

      const base = {
        title,
        artist,
        genius_url: geniusUrl,
        spotify_url: null,
        preview_url: null,
        image: song.song_art_image_url || null,
      };

      try {
        const spToken = await getSpotifyToken();
        const spResp = await axios.get("https://api.spotify.com/v1/search", {
          headers: { Authorization: `Bearer ${spToken}` },
          params: {
            q: `${title} ${artist}`.replace(/[()]/g, ""),
            type: "track",
            limit: 5,
          },
          timeout: 8000,
        });

        // Pega o primeiro resultado com correspondência mais próxima
        const track = spResp.data.tracks.items.find((t) => {
          const name = t.name.toLowerCase();
          const art = t.artists.map((a) => a.name.toLowerCase()).join(" ");
          const s = q.toLowerCase();
          return name.includes(s) || art.includes(s);
        }) || spResp.data.tracks.items[0];

        // Se a busca for em PT, prioriza nomes PT
        if (isPortuguese && track?.name) {
          if (!/[áàãâéêíóôõúç]/i.test(track.name) && Math.random() > 0.4) {
            continue;
          }
        }

        results.push({
          ...base,
          spotify_url: track?.external_urls?.spotify || null,
          preview_url: track?.preview_url || null,
          image: track?.album?.images?.[0]?.url || base.image,
        });
      } catch (err) {
        console.warn("[GENIUS->SPOTIFY] Falhou pra", title, err.message);
        results.push(base);
      }
    }

    // Remove duplicadas pelo título
    const unique = results.filter(
      (v, i, a) => a.findIndex((t) => t.title === v.title) === i
    );

    return res.json(unique);
  } catch (err) {
    console.error("[GENIUS] erro search-lyrics:", err.response?.data || err.message);
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
// Inicializa servidor
// ===============================
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Servidor rodando na porta ${port}`);
});
