
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

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

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    application: "TrustVault",
    timestamp: new Date().toISOString(),
  });
});

module.exports = app;
