const express = require("express");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const crypto = require("node:crypto");
const { pool, initDb } = require("./db");
const { hashKey, newCsrfToken, requireAdmin } = require("./security");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "16kb" }));

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Muitas tentativas. Tente novamente em instantes." }
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

function watermarkConfig() {
  const fontSize = Number.parseInt(process.env.WATERMARK_FONT_SIZE || "24", 10);
  const allowedPositions = new Set([
    "top_left", "top_center", "top_right",
    "center_left", "center", "center_right",
    "bottom_left", "bottom_center", "bottom_right"
  ]);
  const requestedPosition = process.env.WATERMARK_POSITION || "top_center";

  return {
    enabled: process.env.WATERMARK_ENABLED === "true",
    position: allowedPositions.has(requestedPosition) ? requestedPosition : "top_center",
    fontSize: Number.isInteger(fontSize) && fontSize >= 8 && fontSize <= 96 ? fontSize : 24
  };
}

app.get("/health", (_req, res) => res.json({ status: "ok" }));

// Token inicial de sessão. O cliente deve mantê-lo durante a sessão.
app.get("/api/session/", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.status(200).json({ csrfToken: newCsrfToken() });
});

// Valida a key enviada pelo app Android.
app.post("/api/client/access/", authLimiter, async (req, res, next) => {
  try {
    const key = typeof req.body?.key === "string" ? req.body.key.trim() : "";
    if (!key || key.length > 512) {
      return res.status(401).json({
        error: "Key inválida ou expirada.",
        supportUrl: process.env.SUPPORT_URL || "",
        updateUrl: process.env.UPDATE_URL || ""
      });
    }

    const result = await pool.query(
      `SELECT expires_at
         FROM access_keys
        WHERE key_hash = $1
          AND revoked_at IS NULL
          AND (expires_at IS NULL OR expires_at > NOW())
        LIMIT 1`,
      [hashKey(key)]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        error: "Key inválida ou expirada.",
        supportUrl: process.env.SUPPORT_URL || "",
        updateUrl: process.env.UPDATE_URL || ""
      });
    }

    res.set("Cache-Control", "no-store");
    return res.status(200).json({
      csrfToken: newCsrfToken(),
      expires: result.rows[0].expires_at
        ? new Date(result.rows[0].expires_at).toISOString().replace('Z', '+00:00')
        : null,
      watermark: watermarkConfig()
    });
  } catch (err) {
    next(err);
  }
});

// Cria uma key. Duração aceita: 7d, 30d, 90d ou unlimited.
app.post("/api/admin/keys", adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    const duration = req.body?.duration;
    const label = typeof req.body?.label === "string" ? req.body.label.trim().slice(0, 120) : null;
    const daysByDuration = { "7d": 7, "30d": 30, "90d": 90 };
    if (duration !== "unlimited" && !Object.hasOwn(daysByDuration, duration)) {
      return res.status(400).json({
        error: 'duration deve ser "7d", "30d", "90d" ou "unlimited".'
      });
    }

    // O segredo só é exibido nesta resposta; no banco fica apenas o hash.
    const key = `ka_${crypto.randomBytes(32).toString("base64url")}`;
    const expiresAt = duration === "unlimited"
      ? null
      : new Date(Date.now() + daysByDuration[duration] * 24 * 60 * 60 * 1000);

    const result = await pool.query(
      `INSERT INTO access_keys (key_hash, label, expires_at)
       VALUES ($1, $2, $3)
       RETURNING id, label, created_at, expires_at`,
      [hashKey(key), label, expiresAt]
    );

    return res.status(201).json({ key, ...result.rows[0] });
  } catch (err) {
    next(err);
  }
});

// Lista metadados das keys, nunca os tokens originais.
app.get("/api/admin/keys", adminLimiter, requireAdmin, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, label, created_at, expires_at, revoked_at
         FROM access_keys
        ORDER BY created_at DESC
        LIMIT 500`
    );
    res.json({ keys: result.rows });
  } catch (err) {
    next(err);
  }
});

// Revoga uma key pelo ID.
app.delete("/api/admin/keys/:id", adminLimiter, requireAdmin, async (req, res, next) => {
  try {
    if (!/^\d+$/.test(req.params.id)) {
      return res.status(400).json({ error: "ID inválido." });
    }
    const result = await pool.query(
      `UPDATE access_keys
          SET revoked_at = NOW()
        WHERE id = $1 AND revoked_at IS NULL
        RETURNING id`,
      [req.params.id]
    );
    if (result.rowCount === 0) {
      return res.status(404).json({ error: "Key não encontrada ou já revogada." });
    }
    res.json({ success: true, id: result.rows[0].id });
  } catch (err) {
    next(err);
  }
});

app.use((_req, res) => res.status(404).json({ error: "Rota não encontrada." }));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Erro interno do servidor." });
});

async function start() {
  await initDb();
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`KeyAuth API ouvindo na porta ${PORT}`);
  });
}

start().catch((err) => {
  console.error("Falha ao iniciar a API:", err);
  process.exit(1);
});

module.exports = app;