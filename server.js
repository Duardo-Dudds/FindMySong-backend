require("dotenv").config();

const express = require("express");
const cors = require("cors");
const app = express();

// CORS
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://find-my-song.vercel.app",
      "https://find-my-song-frontend.vercel.app",
      "https://findmysong-frontend.vercel.app"
    ],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Garante que o body venha em JSON
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Log simples para ver requisições chegando
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// DB
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    require: true,
    rejectUnauthorized: false,
  },
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

// LOGIN 
app.post("/api/usuarios/login", async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ message: "Preencha email e senha" });
  }

  try {
    console.log(`[LOGIN] Tentando login: ${email}`);

    // Busca o usuário no banco (case-insensitive)
    const r = await pool.query(
      "SELECT * FROM usuarios WHERE LOWER(email) = LOWER($1)",
      [email]
    );

    // Se não existir, para aqui
    if (r.rows.length === 0) {
      console.log(`[LOGIN] Usuário não encontrado: ${email}`);
      return res.status(401).json({ message: "Usuário não encontrado" });
    }

    const user = r.rows[0];

    // Compara a senha
    const senhaCorreta = await bcrypt.compare(senha, user.senha);

    if (!senhaCorreta) {
      console.log(`[LOGIN] Senha incorreta para: ${email}`);
      return res.status(401).json({ message: "Senha incorreta" });
    }

    // Gera token somente se tudo der certo
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
  try {
    const now = Date.now();
    if (cachedToken && now < tokenExpiresAt - 5000) return cachedToken; // 5s de folga

    const clientId = process.env.SPOTIFY_CLIENT_ID;
    const clientSecret = process.env.SPOTIFY_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      console.error("[SPOTIFY] SPOTIFY_CLIENT_ID / SECRET não configurados!");
      throw new Error("Spotify credentials missing");
    }

    const authHeader = "Basic " + Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

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

    if (resp.status !== 200 || !resp.data?.access_token) {
      console.error("[SPOTIFY] Token endpoint respondeu mal:", resp.status, resp.data);
      throw new Error("Token inválido");
    }

    cachedToken = resp.data.access_token;
    tokenExpiresAt = now + (resp.data.expires_in || 3600) * 1000;
    console.log("[SPOTIFY] Token obtido, expira em", resp.data.expires_in, "s");
    return cachedToken;
  } catch (err) {
    console.error("[SPOTIFY] Erro ao gerar token do Spotify:", err.response?.data || err.message || err);
    throw err;
  }
}

// GET /api/spotify/search?q=love
app.get("/api/spotify/search", async (req, res) => {
  try {
    const q = String(req.query.q || "").trim();
    if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório" });

    const token = await getSpotifyToken();

    const r = await axios.get("https://api.spotify.com/v1/search", {
      headers: { Authorization: `Bearer ${token}` },
      params: { q, type: "track", limit: 20 },
      timeout: 8000,
    });

    return res.json(r.data.tracks.items);
  } catch (err) {
    console.error("Erro Spotify search:", err.response?.data || err.message);
    // se for erro de token, devolve 502 para o frontend entender
    if (err.response && err.response.status === 401) {
      return res.status(502).json({ message: "Erro no token do Spotify" });
    }
    return res.status(500).json({ message: "Erro Spotify" });
  }
});

