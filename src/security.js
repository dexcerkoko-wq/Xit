const crypto = require("node:crypto");

function hashKey(key) {
  return crypto.createHash("sha256").update(key, "utf8").digest("hex");
}

function newCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

function requireAdmin(req, res, next) {
  const expected = process.env.ADMIN_SECRET || "";
  const supplied = req.get("x-admin-secret") || "";
  const a = Buffer.from(expected);
  const b = Buffer.from(supplied);

  if (!expected || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: "Não autorizado." });
  }
  next();
}

module.exports = { hashKey, newCsrfToken, requireAdmin };