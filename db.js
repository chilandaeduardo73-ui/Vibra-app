import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";

const { Pool } = pg;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const localFile = path.join(__dirname, "data.json");

let pool = null;
let dbMode = "local";

function loadLocal() {
  if (!fs.existsSync(localFile)) return {};

  try {
    return JSON.parse(fs.readFileSync(localFile, "utf8"));
  } catch {
    return {};
  }
}

function saveLocal(data) {
  fs.writeFileSync(localFile, JSON.stringify(data, null, 2));
}

async function initDb() {
  if (!process.env.DATABASE_URL) {
    dbMode = "local";
    return;
  }

  try {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.DATABASE_SSL === "false"
          ? false
          : { rejectUnauthorized: false }
    });

    await pool.query("SELECT 1");

    await pool.query(`
      CREATE TABLE IF NOT EXISTS vibra_state (
        id INTEGER PRIMARY KEY,
        data JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    dbMode = "postgres";
  } catch (err) {
    console.error("PostgreSQL initialization failed:", err.message);
    pool = null;
    dbMode = "local";
  }
}

async function readState() {
  if (dbMode === "postgres" && pool) {
    const result = await pool.query(
      "SELECT data FROM vibra_state WHERE id = 1"
    );

    return result.rows[0]?.data || {};
  }

  return loadLocal();
}

async function writeState(data) {
  if (dbMode === "postgres" && pool) {
    await pool.query(
      `INSERT INTO vibra_state (id, data)
       VALUES (1, $1)
       ON CONFLICT (id)
       DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
      [data]
    );

    return;
  }

  saveLocal(data);
}

function status() {
  return {
    mode: dbMode,
    postgresConfigured: Boolean(process.env.DATABASE_URL)
  };
}

export { initDb, readState, writeState, status };
