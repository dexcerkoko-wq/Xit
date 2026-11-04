
const express = require("express");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const crypto = require("node:crypto");

const { pool, initDb } = require("./db");
const {
  hashKey,
  newCsrfToken,
  requireAdmin
} = require("./security");

const app = express();
const PORT = Number(process.env.PORT || 3000);

const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "16kb" }));

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: {
    error: "Muitas tentativas. Tente novamente em instantes."
  }
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

function watermarkConfig() {
  const fontSize = Number.parseInt(
    process.env.WATERMARK_FONT_SIZE || "24",
    10
  );

  const allowedPositions = new Set([
    "top_left",
    "top_center",
    "top_right",
    "center_left",
    "center",
    "center_right",
    "bottom_left",
    "bottom_center",
    "bottom_right"
  ]);

  const requestedPosition =
    process.env.WATERMARK_POSITION || "top_center";

  return {
    enabled: process.env.WATERMARK_ENABLED === "true",
    position: allowedPositions.has(requestedPosition)
      ? requestedPosition
      : "top_center",
    fontSize:
      Number.isInteger(fontSize) &&
      fontSize >= 8 &&
      fontSize <= 96
        ? fontSize
        : 24
  };
}

// Health check
app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    service: "KeyAuth API"
  });
});

// Token inicial de sessão
app.get("/api/session/", (_req, res) => {
  res.set("Cache-Control", "no-store");

  res.json({
    csrfToken: newCsrfToken()
  });
});

// Validação da key pelo aplicativo Android
app.post(
  "/api/client/access/",
  authLimiter,
  async (req, res, next) => {
    try {
      const key =
        typeof req.body?.key === "string"
          ? req.body.key.trim()
          : "";

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
            AND expires_at > NOW()
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
        valid: true,
        csrfToken: newCsrfToken(),
        expires: new Date(
          result.rows[0].expires_at
        ).toISOString(),
        watermark: watermarkConfig()
      });

    } catch (err) {
      next(err);
    }
  }
);

// Criar key: validade obrigatória de 7 dias
app.post(
  "/api/admin/keys",
  adminLimiter,
  requireAdmin,
  async (req, res, next) => {
    try {
      const label =
        typeof req.body?.label === "string"
          ? req.body.label.trim().slice(0, 120)
          : null;

      const key =
        "ka_" +
        crypto.randomBytes(32).toString("base64url");

      const expiresAt = new Date(
        Date.now() + SEVEN_DAYS_MS
      );

      const result = await pool.query(
        `INSERT INTO access_keys
          (key_hash, label, expires_at)
         VALUES ($1, $2, $3)
         RETURNING id, label, created_at, expires_at`,
        [
          hashKey(key),
          label,
          expiresAt
        ]
      );

      return res.status(201).json({
        key,
        id: result.rows[0].id,
        label: result.rows[0].label,
        created_at: result.rows[0].created_at,
        expires: new Date(
          result.rows[0].expires_at
        ).toISOString()
      });

    } catch (err) {
      next(err);
    }
  }
);

// Listar keys
app.get(
  "/api/admin/keys",
  adminLimiter,
  requireAdmin,
  async (_req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT
           id,
           label,
           created_at,
           expires_at,
           revoked_at
         FROM access_keys
         ORDER BY created_at DESC
         LIMIT 500`
      );

      res.json({
        keys: result.rows
      });

    } catch (err) {
      next(err);
    }
  }
);

// Revogar key pelo ID
app.delete(
  "/api/admin/keys/:id",
  adminLimiter,
  requireAdmin,
  async (req, res, next) => {
    try {
      if (!/^\d+$/.test(req.params.id)) {
        return res.status(400).json({
          error: "ID inválido."
        });
      }

      const result = await pool.query(
        `UPDATE access_keys
            SET revoked_at = NOW()
          WHERE id = $1
            AND revoked_at IS NULL
          RETURNING id`,
        [req.params.id]
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          error: "Key não encontrada ou já revogada."
        });
      }

      res.json({
        success: true,
        id: result.rows[0].id
      });

    } catch (err) {
      next(err);
    }
  }
);

// Rota não encontrada
app.use((_req, res) => {
  res.status(404).json({
    error: "Rota não encontrada."
  });
});

// Tratamento de erros
app.use((err, _req, res, _next) => {
  console.error(err);

  res.status(500).json({
    error: "Erro interno do servidor."
  });
});

// Inicialização
async function start() {
  await initDb();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(
      `KeyAuth API ouvindo na porta ${PORT}`
    );
  });
}

start().catch((err) => {
  console.error("Falha ao iniciar a API:", err);
  process.exit(1);
});

module.exports = app;
