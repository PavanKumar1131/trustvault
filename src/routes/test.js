
const express = require("express");
const { requireAuth, requireRole } = require("../middleware/auth");

const router = express.Router();

router.get("/protected", requireAuth, (req, res) => {
    res.json({
        message: "You are authenticated",
        user: req.user
    });
});

router.get(
    "/admin",
    requireAuth,
    requireRole("admin"),
    (req, res) => {
        res.json({
            message: "Admin access granted"
        });
    }
);

module.exports = router;
