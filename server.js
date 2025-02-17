const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const bcrypt = require("bcrypt");
const SECRET_KEY = "382782734728";
const app = express();
const PORT = 5000;
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
app.use(express.json());
app.use(cookieParser());

// Enable CORS with credentials (Important for cookies)
app.use(
  cors({
    origin: "http://localhost:3000", // Frontend URL
    credentials: true, // Allow cookies
  })
);

// Connect to SQLite database
const dbPath = path.join(__dirname, "./database.db");
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
  if (err) {
    console.error("Error connecting to database:", err.message);
  } else {
    console.log("Connected to SQLite database.");

    // Read and execute schema.sql
    try {
      const schemaPath = path.join(__dirname, "./schema.sql");
      if (fs.existsSync(schemaPath)) {
        const schemaSQL = fs.readFileSync(schemaPath, "utf8");
        db.exec(schemaSQL, function (err) {
          if (err) {
            console.error("Error executing schema.sql:", err.message);
          } else {
            console.log("Database schema applied.");
            app.listen(PORT, () => {
              console.log(`Server running on http://localhost:${PORT}`);
            });
          }
        });
      } else {
        console.error("schema.sql file not found. Skipping schema setup.");
        app.listen(PORT, () => {
          console.log(`Server running on http://localhost:${PORT}`);
        });
      }
    } catch (err) {
      console.error("Error reading schema.sql:", err.message);
    }
  }
});

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required!" });
  }

  try {
    db.serialize(() => {
      // Ensures queries run sequentially to prevent locking
      const checkUserQuery = `SELECT * FROM users WHERE email = ?`;
      db.get(checkUserQuery, [email], async (err, existingUser) => {
        if (err) {
          return res.status(500).json({ message: "Database error!" });
        }
        if (existingUser) {
          return res
            .status(409)
            .json({ message: "User already exists! Try logging in." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const insertUserQuery = `INSERT INTO users(username, email, password) VALUES (?, ?, ?)`;

        db.run(
          insertUserQuery,
          [username, email, hashedPassword],
          function (err) {
            if (err) {
              return res.status(500).json({ message: "Error saving user!" });
            }
            res.status(201).json({
              message: "User registered successfully!",
              userId: this.lastID,
            });
          }
        );
      });
    });
  } catch (error) {
    res.status(500).json({ message: "Server error! Please try again." });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "All fields are required!" });
  }
  const selectUserQuery = `SELECT * FROM users WHERE email=?`;
  db.get(selectUserQuery, [email], function (err, user) {
    if (err) {
      return res.status(500).json({ error: "Database error" });
    }
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ error: "Server error" });
      if (!isMatch)
        return res.status(401).json({ error: "Invalid credentials" });

      // Generate JWT token
      const jwt_token = jwt.sign(
        { id: user.id, email: user.email },
        SECRET_KEY,
        {
          expiresIn: "1h",
        }
      );
      res.cookie("jwtToken", jwt_token, {
        httpOnly: true, // Prevents JavaScript access
        secure: true, // Ensures HTTPS only (disable for local dev)
        sameSite: "Strict", // Prevents CSRF
        maxAge: 3 * 24 * 60 * 60 * 1000, // 3 days expiry
      });

      res.json({ message: "Login successful", jwt_token });
    });
  });
});

app.post("/notes", async (req, res) => {
  const { content, title, category } = req.body;
  try {
    db.run(
      `INSERT INTO  notes(title, content, category) VALUES (?,?,?);`,
      [content, title, category],
      function (err) {
        if (err) {
          return res.status(500).json({ error: "Server error" });
        }
        res.status(201).json({ message: "note added" });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error! Please try again." });
  }
});
app.put("/notes/", async (req, res) => {
  const { id, content, title, category } = req.body;

  try {
    db.run(
      `UPDATE notes SET content=?,title=?,category=? WHERE id=?`,
      [content, title, category, id],
      function (err) {
        if (err) {
          return res.status(500).json({ error: "Server error" });
        }
        res.status(200).json({ message: "note updated" });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error! Please try again." });
  }
});

app.get("/notes", async (req, res) => {
  try {
    db.all(`SELECT * FROM notes;`, function (err, rows) {
      if (err) {
        return res.status(500).json({ error: "Server error" });
      }
      res.status(200).json({ rows });
      console.log(rows);
    });
  } catch (error) {
    res.status(500).json({ message: "Server error! Please try again." });
  }
});
app.delete("/notes/:id", async (req, res) => {
  const { id } = req.params;
  try {
    db.run(`DELETE FROM notes WHERE id=?;`, [id], function (err, rows) {
      if (err) {
        return res.status(500).json({ error: "Server error" });
      }
      res.status(200).json({ message: "row deleted" });
      console.log(rows);
    });
  } catch (error) {
    res.status(500).json({ message: "Server error! Please try again." });
  }
});
