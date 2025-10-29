const { Pool } = require("pg");
require("dotenv").config();

const pool = new Pool({
  user: process.env.PGUSER,
  host: process.env.PGHOST,
  database: process.env.PGDATABASE,
  password: process.env.PGPASSWORD,
  port: process.env.PGPORT || 5432,
});

pool.connect()
  .then(() => console.log("🟢 Conectado ao PostgreSQL"))
  .catch(err => console.error("🔴 Erro ao conectar ao banco:", err));

module.exports = pool;
