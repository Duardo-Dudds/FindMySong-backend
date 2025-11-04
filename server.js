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
// CORS – libera seus fronts
// ===============================
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "http://localhost:4173",
      "https://findmysong-frontend.vercel.app",
      "https://find-my-song-frontend.vercel.app",
      "https://find-my-song.vercel.app",
      "https://findmysong.vercel.app",
    ],
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Log de todas as requisições
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

// ===============================
// Health check
// ===============================
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
    return res
      .status(201)
      .json({ message: "Usuário criado com sucesso!", usuario: result.rows[0] });
  } catch (err) {
    console.error("Erro ao criar usuário:", err);
    return res.status(500).json({ message: "Erro no servidor." });
  }
});

app.post("/api/usuarios/login", async (req, res) => {
  const { email, senha } = req.body;
  if (!email || !senha)
    return res.status(400).json({ message: "Preencha email e senha." });

  try {
    const result = await pool.query(
      "SELECT * FROM usuarios WHERE LOWER(email) = LOWER($1)",
      [email]
    );
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
    return res.json({ message: "Login bem-sucedido!", token });
  } catch (err) {
    console.error("[LOGIN] Erro inesperado:", err);
    return res.status(500).json({ message: "Erro no servidor." });
  }
});

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
// Spotify Token Cache
// ===============================
let cachedSpotifyToken = null;
let spotifyExpiresAt = 0;

async function getSpotifyToken() {
  const now = Date.now();
  if (cachedSpotifyToken && now < spotifyExpiresAt - 5000)
    return cachedSpotifyToken;

  const clientId = process.env.SPOTIFY_CLIENT_ID;
  const clientSecret = process.env.SPOTIFY_CLIENT_SECRET;
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

  cachedSpotifyToken = resp.data.access_token;
  spotifyExpiresAt = now + resp.data.expires_in * 1000;
  console.log("[SPOTIFY] Novo token gerado.");
  return cachedSpotifyToken;
}

// ===============================
// Spotify – Busca
// ===============================
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
    console.error("[SPOTIFY] Erro na busca:", err.message);
    return res.status(500).json({ message: "Erro na busca Spotify." });
  }
});

// ===============================
// Genius + Spotify – busca por letra
// ===============================
const GENIUS_ACCESS_TOKEN = process.env.GENIUS_ACCESS_TOKEN;
const GENIUS_BASE_URL = "https://api.genius.com";

app.get("/api/search-lyrics", async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório." });
  if (!GENIUS_ACCESS_TOKEN)
    return res.status(500).json({ message: "Chave do Genius não configurada." });

  try {
    const geniusResp = await axios.get(`${GENIUS_BASE_URL}/search`, {
      params: { q: `${q} lyrics song` },
      headers: { Authorization: `Bearer ${GENIUS_ACCESS_TOKEN}` },
      timeout: 9000,
    });

    const hits = geniusResp.data.response?.hits?.slice(0, 25) || [];
    const results = [];

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
          params: { q: `${title} ${artist}`, type: "track", limit: 5 },
        });

        const track = spResp.data.tracks.items[0];
        results.push({
          ...base,
          spotify_url: track?.external_urls?.spotify || null,
          preview_url: track?.preview_url || null,
          image: track?.album?.images?.[0]?.url || base.image,
        });
      } catch {
        results.push(base);
      }
    }

    return res.json(results);
  } catch (err) {
    console.error("[GENIUS] erro search-lyrics:", err.message);
    return res.status(200).json([]);
  }
});

// ===============================
// Spotify – Top 10
// ===============================
app.get("/api/spotify/top10", async (req, res) => {
  try {
    const token = await getSpotifyToken();
    const r = await axios.get("https://api.spotify.com/v1/browse/new-releases", {
      headers: { Authorization: `Bearer ${token}` },
      params: { limit: 10, country: "BR" },
    });

    const tracks = r.data.albums.items.map((album) => ({
      id: album.id,
      title: album.name,
      artist: album.artists[0]?.name,
      image: album.images[0]?.url,
      url: album.external_urls.spotify,
    }));

    res.json(tracks);
  } catch (err) {
    console.error("Erro ao buscar top10:", err.message);
    res.status(500).json({ message: "Erro ao buscar top10." });
  }
});

// ===============================
// Likes (Curtidas)
// ===============================

app.post("/api/likes", async (req, res) => {
  const { usuario_id, spotify_id, titulo, artista, imagem, url } = req.body;

  try {
    await pool.query(
      `INSERT INTO curtidas (usuario_id, spotify_id, titulo, artista, imagem, url)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT DO NOTHING`,
      [usuario_id, spotify_id, titulo, artista, imagem, url]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("[LIKES][INSERT] erro:", e);
    res.status(500).json({ message: "Erro ao curtir música." });
  }
});

// ===============================
// Biblioteca
// ===============================
app.get("/api/library/:usuario_id", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM eduardo.biblioteca WHERE usuario_id = $1 ORDER BY id DESC`,
      [req.params.usuario_id]
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ message: "Erro ao listar biblioteca." });
  }
});

app.post("/api/library", async (req, res) => {
  try {
    const { usuario_id, spotify_id, titulo, artista, imagem, url } = req.body;
    await pool.query(
      `INSERT INTO eduardo.biblioteca (usuario_id, spotify_id, titulo, artista, imagem, url)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [usuario_id, spotify_id, titulo, artista, imagem, url]
    );
    res.json({ message: "Música adicionada à biblioteca!" });
  } catch {
    res.status(500).json({ message: "Erro ao salvar música." });
  }
});

app.delete("/api/library/:spotify_id/:usuario_id", async (req, res) => {
  try {
    await pool.query(
      `DELETE FROM eduardo.biblioteca WHERE spotify_id = $1 AND usuario_id = $2`,
      [req.params.spotify_id, req.params.usuario_id]
    );
    res.json({ message: "Música removida da biblioteca!" });
  } catch {
    res.status(500).json({ message: "Erro ao remover música." });
  }
});

// GET músicas da biblioteca
app.get("/api/library/:userId", async (req, res) => {
  const { userId } = req.params;
  const r = await pool.query("SELECT * FROM biblioteca WHERE usuario_id = $1", [userId]);
  res.json(r.rows);
});

// POST adicionar música
app.post("/api/library", async (req, res) => {
  const { usuario_id, spotify_id, titulo, artista, imagem, url } = req.body;
  await pool.query(
    `INSERT INTO biblioteca (usuario_id, spotify_id, titulo, artista, imagem, url)
     VALUES ($1,$2,$3,$4,$5,$6)
     ON CONFLICT DO NOTHING`,
    [usuario_id, spotify_id, titulo, artista, imagem, url]
  );
  res.json({ ok: true });
});

// GET playlists do usuário
app.get("/api/playlists/:userId", async (req, res) => {
  const { userId } = req.params;
  const r = await pool.query("SELECT * FROM playlists WHERE usuario_id = $1", [userId]);
  res.json(r.rows);
});

// ===============================
// Rotas padrão
// ===============================
app.get("/", (req, res) => res.send("FindMySong backend rodando 🎵"));

app.all("*", (req, res) => {
  console.warn("[404] Rota não encontrada:", req.method, req.url);
  return res
    .status(404)
    .json({ message: "Rota não encontrada no backend", path: req.url });
});

// ===============================
// Inicializa servidor
// ===============================
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`🚀 Servidor rodando na porta ${port}`));
