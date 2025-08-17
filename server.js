import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import pool from "./db.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ----------- Endpoint Login -----------
app.post("/v1/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: "Username dan password wajib" });

  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    if (result.rows.length === 0)
      return res.status(401).json({ error: "User tidak ditemukan" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: "Password salah" });

    res.json({ message: "Login berhasil", user_id: user.id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Terjadi kesalahan server" });
  }
});

// ----------- Endpoint Report -----------
app.post("/v1/report/:context", async (req, res) => {
  const { context } = req.params;
  const { user_id, report_data } = req.body;

  if (!user_id || !report_data)
    return res.status(400).json({ error: "user_id dan report_data wajib" });

  try {
    const result = await pool.query(
      "INSERT INTO reports(user_id, context, data) VALUES($1,$2,$3) RETURNING *",
      [user_id, context, report_data]
    );
    res.json({ message: "Report diterima", report: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Terjadi kesalahan server" });
  }
});

app.listen(PORT, () => console.log(`Server berjalan di port ${PORT}`));
