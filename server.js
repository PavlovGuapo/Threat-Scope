/**
 * THREAT-SCOPE — server.js
 * Backend Express para persistencia de datos en Docker
 */

"use strict";

const express  = require("express");
const multer   = require("multer");
const path     = require("path");
const fs       = require("fs");

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Paths ────────────────────────────────────────────────
const DATA_DIR    = process.env.DATA_DIR    || path.join(__dirname, "data");
const DATA_FILE   = path.join(DATA_DIR, "dashboard.json");
const EVIDENCE_DIR = path.join(DATA_DIR, "evidence");

// Ensure directories exist on startup
fs.mkdirSync(DATA_DIR,    { recursive: true });
fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

// ── Middleware ───────────────────────────────────────────
app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname)));          // static frontend files
app.use("/evidence", express.static(EVIDENCE_DIR));    // serve uploaded images

// ── Multer (evidence uploads) ────────────────────────────
const storage = multer.diskStorage({
  destination: EVIDENCE_DIR,
  filename: (req, file, cb) => {
    const unique = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const ext    = path.extname(file.originalname).toLowerCase() || ".jpg";
    cb(null, unique + ext);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 15 * 1024 * 1024 }, // 15 MB max
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|bmp/;
    if (allowed.test(path.extname(file.originalname).toLowerCase()) &&
        allowed.test(file.mimetype.split("/")[1])) {
      cb(null, true);
    } else {
      cb(new Error("Solo se permiten imágenes (jpg, png, gif, webp, bmp)"));
    }
  }
});

// ── API: Dashboard data ───────────────────────────────────

/** GET /api/data — carga el dashboard guardado */
app.get("/api/data", (req, res) => {
  if (!fs.existsSync(DATA_FILE)) return res.json({});
  try {
    const raw  = fs.readFileSync(DATA_FILE, "utf8");
    const data = JSON.parse(raw);
    res.json(data);
  } catch (err) {
    console.error("Error leyendo datos:", err.message);
    res.json({});
  }
});

/** POST /api/data — guarda el estado completo */
app.post("/api/data", (req, res) => {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(req.body, null, 2), "utf8");
    res.json({ ok: true });
  } catch (err) {
    console.error("Error guardando datos:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── API: Evidence ─────────────────────────────────────────

/** POST /api/evidence — sube una imagen de evidencia */
app.post("/api/evidence", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No se recibió archivo" });
  res.json({
    filename: req.file.filename,
    url:      `/evidence/${req.file.filename}`,
    size:     req.file.size
  });
});

/** DELETE /api/evidence/:filename — elimina una imagen */
app.delete("/api/evidence/:filename", (req, res) => {
  // Sanitize: no path traversal
  const safe = path.basename(req.params.filename);
  const file = path.join(EVIDENCE_DIR, safe);
  if (fs.existsSync(file)) {
    fs.unlinkSync(file);
  }
  res.json({ ok: true });
});

/** GET /api/health — healthcheck para Docker */
app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

// ── Error handler ────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err.message);
  res.status(400).json({ error: err.message });
});

// ── Start ────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅  Threat-Scope corriendo en http://0.0.0.0:${PORT}`);
  console.log(`📁  Datos en: ${DATA_DIR}`);
});