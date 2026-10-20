
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const pool = require("./db");

const app = express();

app.use(helmet());

app.use(express.json({ limit: "1mb" }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  })
);

// Application health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    application: "TrustVault",
    timestamp: new Date().toISOString(),
  });
});

// PostgreSQL database health check
app.get("/api/health/db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS database_time");

    res.json({
      status: "ok",
      database: "connected",
      timestamp: result.rows[0].database_time,
    });
  } catch (error) {
    console.error("Database health check failed:", error.message);

    res.status(503).json({
      status: "error",
      database: "unavailable",
    });
  }
});

module.exports = app;
