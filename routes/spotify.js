const express = require("express");
const axios = require("axios");
const router = express.Router();

let cachedToken = null;
let tokenExpiresAt = 0;

async function getAppToken() {
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
  // spotify costuma dar expires_in ~3600s
  tokenExpiresAt = now + (resp.data.expires_in - 60) * 1000; // renova 1 min antes
  return cachedToken;
}

// GET /api/spotify/search?q=love
router.get("/search", async (req, res) => {
  try {
    const q = req.query.q;
    if (!q) return res.status(400).json({ message: "Parâmetro q é obrigatório" });

    const token = await getAppToken();
    const r = await axios.get("https://api.spotify.com/v1/search", {
      headers: { Authorization: `Bearer ${token}` },
      params: { q, type: "track", limit: 20 },
    });

    return res.json(r.data.tracks.items);
  } catch (err) {
    console.error("Erro Spotify:", err.response?.data || err.message);
    return res.status(500).json({ message: "Erro Spotify" });
  }
});

module.exports = router;
