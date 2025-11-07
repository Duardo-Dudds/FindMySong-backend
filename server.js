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

// Log de requisições
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
// Curtidas (Likes)
// ===============================
app.get("/api/likes/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const result = await pool.query(
      "SELECT * FROM curtidas WHERE usuario_id = $1 ORDER BY id DESC",
      [userId]
    );
    res.json(result.rows);
  } catch (e) {
    console.error("[LIKES][GET] erro:", e);
    res.status(500).json({ message: "Erro ao buscar curtidas." });
  }
});

app.post("/api/likes", async (req, res) => {
  const { usuario_id, spotify_id, titulo, artista, imagem, url } = req.body;
  try {
    await pool.query(
      `INSERT INTO curtidas (usuario_id, spotify_id, titulo, artista, imagem, url)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (usuario_id, spotify_id) DO NOTHING`,
      [usuario_id, spotify_id, titulo, artista, imagem, url]
    );
    res.json({ message: "Música curtida com sucesso!" });
  } catch (e) {
    console.error("[LIKES][INSERT] erro:", e);
    res.status(500).json({ message: "Erro ao curtir música." });
  }
});

app.delete("/api/likes/:spotifyId/:userId", async (req, res) => {
  const { spotifyId, userId } = req.params;
  try {
    await pool.query(
      "DELETE FROM curtidas WHERE usuario_id = $1 AND spotify_id = $2",
      [userId, spotifyId]
    );
    res.json({ message: "Música removida das curtidas!" });
  } catch (e) {
    console.error("[LIKES][DELETE] erro:", e);
    res.status(500).json({ message: "Erro ao remover curtida." });
  }
});

// ===============================
// Biblioteca
// ===============================
app.get("/api/library/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const r = await pool.query(
      "SELECT * FROM biblioteca WHERE usuario_id = $1 ORDER BY id DESC",
      [userId]
    );
    res.json(r.rows);
  } catch {
    res.status(500).json({ message: "Erro ao listar biblioteca." });
  }
});

app.post("/api/library", async (req, res) => {
  const { usuario_id, spotify_id, titulo, artista, imagem, url } = req.body;
  try {
    await pool.query(
      `INSERT INTO biblioteca (usuario_id, spotify_id, titulo, artista, imagem, url)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (usuario_id, spotify_id) DO NOTHING`,
      [usuario_id, spotify_id, titulo, artista, imagem, url]
    );
    res.json({ message: "Música adicionada à biblioteca!" });
  } catch {
    res.status(500).json({ message: "Erro ao salvar música." });
  }
});

app.delete("/api/library/:spotifyId/:userId", async (req, res) => {
  const { spotifyId, userId } = req.params;
  try {
    await pool.query(
      "DELETE FROM biblioteca WHERE spotify_id = $1 AND usuario_id = $2",
      [spotifyId, userId]
    );
    res.json({ message: "Música removida da biblioteca!" });
  } catch {
    res.status(500).json({ message: "Erro ao remover música." });
  }
});

// ===============================
// Playlists
// ===============================
app.get("/api/playlists/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const r = await pool.query(
      "SELECT * FROM playlists WHERE usuario_id = $1 ORDER BY id DESC",
      [userId]
    );
    res.json(r.rows);
  } catch {
    res.status(500).json({ message: "Erro ao buscar playlists." });
  }
});

// ===============================
// Rota para salvar configs
// ===============================

app.post("/api/admin/config", async (req, res) => {
  try {
    const data = req.body;
    await pool.query(
      `INSERT INTO configuracoes (site_name, theme, items_per_page, language, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (id) DO UPDATE SET
         site_name = $1,
         theme = $2,
         items_per_page = $3,
         language = $4,
         updated_at = NOW()`,
      [data.site_name, data.theme, data.items_per_page, data.language]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error("[ADMIN CONFIG ERROR]", err);
    res.status(500).json({ message: "Erro ao salvar configurações." });
  }
});
// ===============================
// ADMIN – Configurações e Temas
// ===============================

// Retorna as configurações atuais
app.get("/api/admin/config", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT site_name, theme, items_per_page, language FROM configuracoes ORDER BY updated_at DESC LIMIT 1"
    );

    if (result.rows.length === 0) {
      return res.json({
        site_name: "FindMySong",
        theme: "light",
        items_per_page: 20,
        language: "pt-BR",
      });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("[ADMIN CONFIG GET ERROR]", err);
    res.status(500).json({ message: "Erro ao buscar configurações." });
  }
});

// Salva/atualiza configurações
app.post("/api/admin/config", async (req, res) => {
  try {
    const data = req.body;

    await pool.query(
      `INSERT INTO configuracoes (site_name, theme, items_per_page, language, updated_at)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (id) DO UPDATE
       SET site_name = $1,
           theme = $2,
           items_per_page = $3,
           language = $4,
           updated_at = NOW();`,
      [
        data.site_name || "FindMySong",
        data.theme || "light",
        data.items_per_page || 20,
        data.language || "pt-BR",
      ]
    );

    res.json({ ok: true, message: "Configurações salvas com sucesso!" });
  } catch (err) {
    console.error("[ADMIN CONFIG POST ERROR]", err);
    res.status(500).json({ message: "Erro ao salvar configurações." });
  }
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


