import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import crypto from "crypto";
import pool from "./db.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Middleware
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ status: "failed", message: "Token diperlukan" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const result = await pool.query("SELECT * FROM users WHERE token = $1", [token]);
    if (result.rows.length === 0) {
      return res.status(401).json({ status: "failed", message: "Token tidak valid" });
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    console.error("Auth error:", err);
    res.status(500).json({ status: "failed", message: "Terjadi kesalahan server" });
  }
}

// LOGIN 
app.post("/v1/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ status: "failed", message: "Username dan password wajib" });

  try {
    let result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    let user;

    if (result.rows.length === 0) {
      
      const password_hash = await bcrypt.hash(password, 10);
      const token = crypto.randomBytes(32).toString("hex");
      const insertResult = await pool.query(
        "INSERT INTO users(username,password_hash,token) VALUES($1,$2,$3) RETURNING *",
        [username, password_hash, token]
      );
      user = insertResult.rows[0];
    } else {
      user = result.rows[0];
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match)
        return res.status(401).json({ status: "failed", message: "Password salah" });
      
      // Refresh token
      const newToken = crypto.randomBytes(32).toString("hex");
      const updateResult = await pool.query(
        "UPDATE users SET token=$1 WHERE id=$2 RETURNING *",
        [newToken, user.id]
      );
      user = updateResult.rows[0];
    }

    res.json({
      status: "success",
      message: "Login berhasil",
      username: user.username,
      token: user.token
    });
  } catch (err) {
    console.error("Error di login:", err);
    res.status(500).json({ status: "failed", message: "Terjadi kesalahan server" });
  }
});

// ATTENDANCE
app.post("/v1/report/attendance", authMiddleware, async (req, res) => {
  const { status, reason } = req.body;
  if (!status) return res.status(400).json({ status: "failed", message: "status wajib diisi" });

  try {
    await pool.query(
      "INSERT INTO attendance(user_id, status, reason) VALUES($1,$2,$3)",
      [req.user.id, status, reason || null]
    );
    res.json({ status: "success", message: "Attendance berhasil disimpan" });
  } catch (err) {
    console.error("Error attendance:", err);
    res.status(500).json({ status: "failed", message: "Terjadi kesalahan server" });
  }
});

// SUBMIT PRODUCT
app.post("/v1/report/submit-product", authMiddleware, async (req, res) => {
  const products = req.body;
  if (!Array.isArray(products) || products.length === 0) {
    return res.status(400).json({ status: "failed", message: "Data produk tidak valid" });
  }

  try {
    for (const p of products) {
      await pool.query(
        `UPDATE product 
         SET is_available = $1, created_at = CURRENT_TIMESTAMP 
         WHERE user_id = $2 AND product_id = $3`,
        [p.is_available, req.user.id, p.product_id]
      );
    }
    res.json({ status: "success", message: "Product report berhasil diupdate" });
  } catch (err) {
    console.error("Error submit-product:", err);
    res.status(500).json({ status: "failed", message: "Terjadi kesalahan server" });
  }
});


// SUBMIT PROMO 
app.post("/v1/report/submit-promo", authMiddleware, async (req, res) => {
  const { store_name, product_name, product_price, promo_price } = req.body;
  if (!store_name || !product_name || !product_price || !promo_price)
    return res.status(400).json({ status: "failed", message: "Semua field wajib diisi" });

  try {
    await pool.query(
      "INSERT INTO promo(user_id, store_name, product_name, product_price, promo_price) VALUES($1,$2,$3,$4,$5)",
      [req.user.id, store_name, product_name, product_price, promo_price]
    );
    res.json({ status: "success", message: "Promo report berhasil disimpan" });
  } catch (err) {
    console.error("Error submit-promo:", err);
    res.status(500).json({ status: "failed", message: "Terjadi kesalahan server" });
  }
});

app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
