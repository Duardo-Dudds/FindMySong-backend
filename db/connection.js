const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.connect()
  .then(() => {
    console.log("🟢 Conectado ao PostgreSQL Render");
    pool.query('SET search_path TO eduardo, public;');
  })
  .catch(err => console.error("🔴 Erro ao conectar ao banco:", err));

module.exports = pool;
