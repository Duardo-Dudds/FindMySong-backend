// ========================================
//  Configurações principais e variáveis
// ========================================

// Carrega variáveis de ambiente (.env)
require("dotenv").config();

// Dependências principais
const express = require("express");
const cors = require("cors");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

// ========================================
//  Configuração de CORS
// ========================================
// Permitindo acesso apenas do meu front hospedado (Vercel) e localhost para testes
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

// Garante que o corpo das requisições venha em JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Log simples pra saber o que o servidor está recebendo
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ========================================
//  Banco de Dados (PostgreSQL - Render)
// ========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false },
});

// Teste rápido pra saber se o backend está vivo
app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ========================================
//  Rotas de Usuário (cadastro / login)
// ========================================

// Cadastro de usuário
app.post("/api/usuarios/register", async (req, res) => {
  const { nome, email, senha } = req.body;

  if (!nome || !email || !senha)
    return res.status(400).json({ message: "Preencha todos os campos." });

  try {
    const senhaHash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      "INSERT INTO usuarios (nome, email, senha) VALUES ($1,$2,$3) RETURNING id, nome, email",
      [nome, email, senhaHash]
    );
    res.status(201).json({ message: "Usuário criado com sucesso!", usuario: result.rows[0] });
  } catch (err) {
    console.error("Erro ao criar usuário:", err);
    res.status(500).json({ message: "Erro no servidor." });
  }
});

// Login do usuário
app.post("/api/usuarios/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha)
    return res.status(400).json({ message: "Preencha email e senha." });

  try {
    console.log(`[LOGIN] Tentando login: ${email}`);

    const result = await pool.query("SELECT * FROM usuarios WHERE LOWER(email)=LOWER($1)", [email]);
    if (result.rows.length === 0)
      return res.status(401).json({ message: "Usuário não encontrado." });

    const user = result.rows[0];
    const senhaCorreta = await bcrypt.compare(senha, user.senha);

    if (!senhaCorreta)
      return res.status(401).json({ message: "Senha incorreta." });

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET || "segredo123",
      { expiresIn: "7d" }
    );

    console.log(`[LOGIN] Login bem-sucedido: ${email}`);
    res.json({ message: "Login bem-sucedido!", token });
  } catch (err) {
    console.error("[LOGIN] Erro inesperado:", err);
    res.status(500).json({ message: "Erro no servidor." });
  }
});

// Rota protegida básica
app.get("/api/usuarios/me", async (req, res) => {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.replace("Bearer ", "");
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const result = await pool.query("SELECT id, nome, email FROM usuarios WHERE id = $1", [payload.id]);
    res.json(result.rows[0]);
  } catch {
    res.status(401).json({ message: "Não autorizado." });
  }
});

// ========================================
//  Integração com Spotify API
// ========================================
let cachedToken = null;
let tokenExpiresAt = 0;

async function getSpotifyToken() {
  try {
    const now = Date.now();
    if (cachedToken && now < tokenExpiresAt - 5000) return cachedToken;

    const clientId = process.env.SPOTIFY_CLIENT_ID;
    const clientSecret = process.env.SPOTIFY_CLIENT_SECRET;

    if (!clientId || !clientSecret)
      throw new Error("Spotify Client ID ou Secret não configurados.");

    const authHeader = "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

    const resp = await axios.post(
      "https://accounts.spotify.com/api/token",
      new URLSearchParams({ grant_type: "client_credentials" }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: authHeader } }
    );

    if (!resp.data?.access_token)
      throw new Error("Erro ao gerar token do Spotify.");

    cachedToken = resp.data.access_token;
    tokenExpiresAt = now + resp.data.expires_in * 1000;

    console.log(`[SPOTIFY] Token gerado. Expira em ${resp.data.expires_in}s.`);
    return cachedToken;
  } catch (err) {
    console.error("[SPOTIFY] Erro:", err.response?.data || err.message);
    throw err;
  }
}

// Busca direta no Spotify
app.get("/api/spotify/search", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório." });

    const token = await getSpotifyToken();
    const r = await axios.get("https://api.spotify.com/v1/search", {
      headers: { Authorization: `Bearer ${token}` },
      params: { q, type: "track", limit: 20 },
    });

    res.json(r.data.tracks.items);
  } catch (err) {
    console.error("[SPOTIFY] Erro na busca:", err.response?.data || err.message);
    res.status(500).json({ message: "Erro na busca Spotify." });
  }
});

// ========================================
//  Integração com Genius API
// ========================================
const GENIUS_ACCESS_TOKEN = process.env.GENIUS_ACCESS_TOKEN;
const GENIUS_BASE_URL = "https://api.genius.com";

// Busca letras no Genius + complementa com dados do Spotify
app.get("/api/search-lyrics", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório." });

    if (!GENIUS_ACCESS_TOKEN)
      return res.status(500).json({ message: "Chave Genius não configurada." });

    // Busca no Genius
    const geniusRes = await axios.get(`${GENIUS_BASE_URL}/search`, {
      params: { q },
      headers: { Authorization: `Bearer ${GENIUS_ACCESS_TOKEN}` },
    });

    const hits = geniusRes.data.response.hits.slice(0, 8);
    const results = [];

    // Para cada resultado do Genius, tenta achar no Spotify
    for (const hit of hits) {
      const song = hit.result;
      const title = song.title;
      const artist = song.primary_artist?.name;

      try {
        const spToken = await getSpotifyToken();
        const spRes = await axios.get("https://api.spotify.com/v1/search", {
          headers: { Authorization: `Bearer ${spToken}` },
          params: { q: `${title} ${artist}`, type: "track", limit: 1 },
        });

        const track = spRes.data.tracks.items[0];

        results.push({
          title,
          artist,
          genius_url: song.url,
          spotify_url: track?.external_urls?.spotify || null,
          preview_url: track?.preview_url || null,
          image: track?.album?.images?.[0]?.url || null,
        });
      } catch {
        results.push({
          title,
          artist,
          genius_url: song.url,
          spotify_url: null,
          preview_url: null,
          image: null,
        });
      }
    }

    res.json(results);
  } catch (err) {
    console.error("[GENIUS] Erro na busca:", err.response?.data || err.message);
    res.status(500).json({ message: "Erro na busca de letras." });
  }
});

// ========================================
// Inicialização do servidor
// ========================================
const port = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send("FindMySong Backend está rodando 🎵");
});

app.listen(port, () => {
  console.log(`🚀 Servidor rodando na porta ${port}`);
});
