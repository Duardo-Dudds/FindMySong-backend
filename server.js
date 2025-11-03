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

// aceita JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// log de TODA requisição que CHEGAR no Express
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

// GET /api/usuarios/me
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
// Spotify – com cache (NO BACKEND)
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
    console.error("[SPOTIFY] Credenciais não configuradas");
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
    console.error("[SPOTIFY] resposta ruim:", resp.data);
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
    if (!q) {
      return res.status(400).json({ message: "Parâmetro q é obrigatório." });
    }

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

// GET /api/spotify/top10 – Top 10 da semana (pega da playlist Top 50 Brasil)
app.get("/api/spotify/top10", async (req, res) => {
  try {
    const token = await getSpotifyToken();

    // playlist Top 50 Brasil
    const playlistId = "37i9dQZEVXbMXbN3EUUhlg";

    const r = await axios.get(`https://api.spotify.com/v1/playlists/${playlistId}`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 8000,
    });

    const tracks = (r.data.tracks.items || [])
      .slice(0, 10)
      .map((item) => {
        const t = item.track;
        return {
          id: t.id,
          title: t.name,
          artist: t.artists.map((a) => a.name).join(", "),
          image: t.album.images?.[0]?.url || "",
          url: t.external_urls?.spotify || "",
          preview_url: t.preview_url || null,
        };
      });

    return res.json(tracks);
  } catch (err) {
    console.error("[SPOTIFY TOP10] erro:", err.response?.data || err.message);
    return res.status(200).json([]);
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

    const allHits = geniusResp.data.response?.hits || [];

    const hits = allHits
      .filter((h) => {
        const title = h.result.title.toLowerCase();
        const artist = h.result.primary_artist?.name?.toLowerCase() || "";
        const search = q.toLowerCase();
        return title.includes(search) || artist.includes(search);
      })
      .slice(0, 25);

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
          params: {
            q: `${title} ${artist}`.replace(/[()]/g, ""),
            type: "track",
            limit: 5,
          },
          timeout: 8000,
        });

        const track =
          spResp.data.tracks.items.find((t) => {
            const name = t.name.toLowerCase();
            const arts = t.artists.map((a) => a.name.toLowerCase()).join(" ");
            const s = q.toLowerCase();
            return name.includes(s) || arts.includes(s);
          }) || spResp.data.tracks.items[0];

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

    return res.json(results);
  } catch (err) {
    console.error("[GENIUS] erro search-lyrics:", err.response?.data || err.message);
    return res.status(200).json([]);
  }
});

// ===============================
// Letras – backend devolve HTML ou só o link
// ===============================
app.get("/api/lyrics/html", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).json({ message: "URL obrigatória" });

  try {
    const r = await axios.get(url, { timeout: 8000 });
    return res.json({ html: r.data });
  } catch (err) {
    console.error("[LYRICS] erro ao puxar html:", err.message);
    return res.json({ html: null, url });
  }
});

// ===============================
// Likes
// ===============================

// GET /api/likes/:usuario_id
app.get("/api/likes/:usuario_id", async (req, res) => {
  const { usuario_id } = req.params;
  try {
    const r = await pool.query(
      "SELECT spotify_id, titulo, artista, imagem, url FROM likes WHERE usuario_id = $1",
      [usuario_id]
    );
    return res.json(r.rows);
  } catch (err) {
    console.error("[LIKES] erro ao listar:", err.message);
    return res.status(500).json({ message: "Erro ao listar likes" });
  }
});

// POST /api/likes
app.post("/api/likes", async (req, res) => {
  const { usuario_id, spotify_id, titulo, artista, imagem, url } = req.body;
  if (!usuario_id || !spotify_id || !titulo) {
    return res.status(400).json({ message: "Dados incompletos para like" });
  }

  try {
    await pool.query(
      "INSERT INTO likes (usuario_id, spotify_id, titulo, artista, imagem, url) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
      [usuario_id, spotify_id, titulo, artista || "", imagem || "", url || ""]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("[LIKES] erro ao inserir:", err.message);
    return res.status(500).json({ message: "Erro ao inserir like" });
  }
});

// DELETE /api/likes/:spotify_id/:usuario_id
app.delete("/api/likes/:spotify_id/:usuario_id", async (req, res) => {
  const { spotify_id, usuario_id } = req.params;
  try {
    await pool.query(
      "DELETE FROM likes WHERE spotify_id = $1 AND usuario_id = $2",
      [spotify_id, usuario_id]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("[LIKES] erro ao deletar:", err.message);
    return res.status(500).json({ message: "Erro ao deletar like" });
  }
});

// ===============================
// Biblioteca
// ===============================

// GET /api/library/:usuario_id
app.get("/api/library/:usuario_id", async (req, res) => {
  const { usuario_id } = req.params;
  try {
    const r = await pool.query(
      "SELECT spotify_id, titulo, artista, imagem, url FROM biblioteca WHERE usuario_id = $1",
      [usuario_id]
    );
    return res.json(r.rows);
  } catch (err) {
    console.error("[LIBRARY] erro ao listar:", err.message);
    return res.status(500).json({ message: "Erro ao listar biblioteca" });
  }
});

// POST /api/library
app.post("/api/library", async (req, res) => {
  const { usuario_id, spotify_id, titulo, artista, imagem, url } = req.body;
  if (!usuario_id || !spotify_id || !titulo) {
    return res.status(400).json({ message: "Dados incompletos para biblioteca" });
  }

  try {
    await pool.query(
      "INSERT INTO biblioteca (usuario_id, spotify_id, titulo, artista, imagem, url) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
      [usuario_id, spotify_id, titulo, artista || "", imagem || "", url || ""]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("[LIBRARY] erro ao inserir:", err.message);
    return res.status(500).json({ message: "Erro ao inserir na biblioteca" });
  }
});

// DELETE /api/library/:spotify_id/:usuario_id
app.delete("/api/library/:spotify_id/:usuario_id", async (req, res) => {
  const { spotify_id, usuario_id } = req.params;
  try {
    await pool.query(
      "DELETE FROM biblioteca WHERE spotify_id = $1 AND usuario_id = $2",
      [spotify_id, usuario_id]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("[LIBRARY] erro ao deletar:", err.message);
    return res.status(500).json({ message: "Erro ao deletar da biblioteca" });
  }
});

// ===============================
// Playlists
// ===============================

// GET /api/playlists/:usuario_id
app.get("/api/playlists/:usuario_id", async (req, res) => {
  const { usuario_id } = req.params;
  try {
    const r = await pool.query(
      "SELECT id, nome, descricao, criada_em FROM playlists WHERE usuario_id = $1 ORDER BY criada_em DESC",
      [usuario_id]
    );
    return res.json(r.rows);
  } catch (err) {
    console.error("[PLAYLIST] erro ao listar:", err.message);
    return res.status(500).json({ message: "Erro ao listar playlists" });
  }
});

// POST /api/playlists
app.post("/api/playlists", async (req, res) => {
  const { usuario_id, nome, descricao } = req.body;
  if (!usuario_id || !nome) {
    return res.status(400).json({ message: "Dados incompletos para playlist" });
  }

  try {
    const r = await pool.query(
      "INSERT INTO playlists (usuario_id, nome, descricao) VALUES ($1,$2,$3) RETURNING id, nome, descricao, criada_em",
      [usuario_id, nome, descricao || null]
    );
    return res.status(201).json(r.rows[0]);
  } catch (err) {
    console.error("[PLAYLIST] erro ao criar:", err.message);
    return res.status(500).json({ message: "Erro ao criar playlist" });
  }
});

// GET /api/playlists/:playlist_id/musicas
app.get("/api/playlists/:playlist_id/musicas", async (req, res) => {
  const { playlist_id } = req.params;
  try {
    const r = await pool.query(
      "SELECT spotify_id, titulo, artista, imagem, url FROM playlist_musicas WHERE playlist_id = $1 ORDER BY adicionada_em DESC",
      [playlist_id]
    );
    return res.json(r.rows);
  } catch (err) {
    console.error("[PLAYLIST] erro ao listar músicas:", err.message);
    return res.status(500).json({ message: "Erro ao listar músicas da playlist" });
  }
});

// POST /api/playlists/:playlist_id/musicas
app.post("/api/playlists/:playlist_id/musicas", async (req, res) => {
  const { playlist_id } = req.params;
  const { spotify_id, titulo, artista, imagem, url } = req.body;

  if (!spotify_id || !titulo) {
    return res.status(400).json({ message: "Dados incompletos para adicionar música" });
  }

  try {
    await pool.query(
      "INSERT INTO playlist_musicas (playlist_id, spotify_id, titulo, artista, imagem, url) VALUES ($1,$2,$3,$4,$5,$6)",
      [playlist_id, spotify_id, titulo, artista || "", imagem || "", url || ""]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("[PLAYLIST] erro ao adicionar música:", err.message);
    return res.status(500).json({ message: "Erro ao adicionar música" });
  }
});

// DELETE /api/playlists/:playlist_id/musicas/:spotify_id
app.delete("/api/playlists/:playlist_id/musicas/:spotify_id", async (req, res) => {
  const { playlist_id, spotify_id } = req.params;
  try {
    await pool.query(
      "DELETE FROM playlist_musicas WHERE playlist_id = $1 AND spotify_id = $2",
      [playlist_id, spotify_id]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error("[PLAYLIST] erro ao remover música:", err.message);
    return res.status(500).json({ message: "Erro ao remover música" });
  }
});

// ===============================
// Rota raiz
// ===============================
app.get("/", (req, res) => {
  res.send("FindMySong backend rodando 🎵");
});

// ===============================
// 404 GLOBAL – IMPORTANTE
// ===============================
app.all("*", (req, res) => {
  console.warn("[404] Rota não encontrada:", req.method, req.url);
  return res.status(404).json({
    message: "Rota não encontrada no backend",
    method: req.method,
    path: req.url,
  });
});

// ===============================
// Inicializa servidor
// ===============================
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚀 Servidor rodando na porta ${port}`);
});
