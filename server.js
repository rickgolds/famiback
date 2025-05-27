const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

console.log("JWT_SECRET:", process.env.JWT_SECRET);

// Configure CORS to allow only the Vercel frontend domain
app.use(
  cors({
    origin: "https://famiback-production.up.railway.app", // Replace with your Vercel URL
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Błąd połączenia z MySQL:", err);
    return;
  }
  console.log("Połączono z MySQL");
});

// Middleware do weryfikacji tokena JWT z tolerancją zegara
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    console.log("Brak tokena w żądaniu");
    return res.status(401).json({ error: "Brak tokena" });
  }

  console.log("Token otrzymany:", token);
  jwt.verify(
    token,
    process.env.JWT_SECRET,
    { clockTolerance: 300 },
    (err, user) => {
      // 300 seconds = 5 minutes tolerance
      if (err) {
        console.error("Błąd weryfikacji tokena:", err.message);
        console.error("Aktualny czas serwera:", new Date().toISOString());
        console.error(
          "Token exp:",
          new Date(jwt.decode(token).exp * 1000).toISOString()
        );
        return res
          .status(403)
          .json({ error: "Nieprawidłowy token", details: err.message });
      }
      console.log("Zweryfikowany użytkownik:", user);
      req.user = user;
      next();
    }
  );
};

// Rejestracja (Sign Up)
app.post("/signup", async (req, res) => {
  const { name, lastname, email, nickname, password, confirmPassword } =
    req.body;

  if (
    !name ||
    !lastname ||
    !email ||
    !nickname ||
    !password ||
    !confirmPassword
  ) {
    return res.status(400).json({ error: "Wszystkie pola są wymagane" });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ error: "Hasła nie są identyczne" });
  }

  try {
    db.query(
      "SELECT email, nickname FROM users WHERE email = ? OR nickname = ?",
      [email, nickname],
      async (err, results) => {
        if (err) {
          console.error("Błąd zapytania SQL (SELECT):", err);
          return res.status(500).json({ error: "Błąd serwera" });
        }
        if (results.length > 0) {
          if (results.some((user) => user.email === email)) {
            return res.status(400).json({ error: "Email już istnieje" });
          }
          if (results.some((user) => user.nickname === nickname)) {
            return res.status(400).json({ error: "Nickname już istnieje" });
          }
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
          "INSERT INTO users (name, lastname, email, nickname, password, total_points) VALUES (?, ?, ?, ?, ?, ?)",
          [name, lastname, email, nickname, hashedPassword, 0],
          (err) => {
            if (err) {
              console.error("Błąd zapytania SQL (INSERT):", err);
              return res.status(500).json({
                error: "Błąd podczas rejestracji",
                details: err.message,
              });
            }
            res.status(201).json({ message: "Użytkownik zarejestrowany" });
          }
        );
      }
    );
  } catch (error) {
    console.error("Błąd ogólny:", error);
    res.status(500).json({ error: "Błąd serwera", details: error.message });
  }
});

// Logowanie (Sign In)
app.post("/signin", (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: "Identyfikator i hasło są wymagane" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ? OR nickname = ?",
    [identifier, identifier],
    async (err, results) => {
      if (err) {
        console.error("Błąd zapytania SQL (SELECT):", err);
        return res.status(500).json({ error: "Błąd serwera" });
      }
      if (results.length === 0) {
        return res
          .status(400)
          .json({ error: "Nieprawidłowy identyfikator lub hasło" });
      }

      const user = results[0];

      const isValid = await bcrypt.compare(password, user.password);
      if (!isValid) {
        return res
          .status(400)
          .json({ error: "Nieprawidłowy identyfikator lub hasło" });
      }

      const token = jwt.sign(
        {
          id: user.id,
          email: user.email,
          name: user.name,
          lastname: user.lastname,
        },
        process.env.JWT_SECRET,
        { expiresIn: "2h" } // Increased to 2 hours for better user experience
      );
      res.json({ token, message: "Zalogowano pomyślnie" });
    }
  );
});

// Pobierz wszystkich użytkowników
app.get("/users", authenticateToken, (req, res) => {
  db.query(
    "SELECT id, name, lastname, total_points FROM users",
    (err, results) => {
      if (err) {
        console.error("Błąd zapytania SQL (SELECT users):", err);
        return res.status(500).json({ error: "Błąd serwera" });
      }
      res.json(results);
    }
  );
});

// Pobierz wszystkie listy zadań
app.get("/task-lists", authenticateToken, (req, res) => {
  db.query(
    "SELECT DISTINCT tl.* " +
      "FROM task_lists tl " +
      "LEFT JOIN list_users lu ON tl.id = lu.list_id " +
      "WHERE tl.created_by = ? OR lu.user_id = ?",
    [req.user.id, req.user.id],
    (err, results) => {
      if (err) {
        console.error("Błąd zapytania SQL (SELECT task_lists):", err);
        return res.status(500).json({ error: "Błąd serwera" });
      }
      res.json(results);
    }
  );
});

// Dodaj nową listę zadań
app.post("/task-lists", authenticateToken, (req, res) => {
  const { name } = req.body;
  const created_by = req.user.id;

  if (!name) {
    return res.status(400).json({ error: "Nazwa listy jest wymagana" });
  }

  db.query(
    "INSERT INTO task_lists (name, created_by) VALUES (?, ?)",
    [name, created_by],
    (err) => {
      if (err) {
        console.error("Błąd zapytania SQL (INSERT task_list):", err);
        return res.status(500).json({ error: "Błąd podczas dodawania listy" });
      }
      res.status(201).json({ message: "Lista dodana" });
    }
  );
});

// Edytuj nazwę listy
app.put("/task-lists/:id", authenticateToken, (req, res) => {
  const listId = req.params.id;
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Nazwa listy jest wymagana" });
  }

  db.query(
    "UPDATE task_lists SET name = ? WHERE id = ? AND created_by = ?",
    [name, listId, req.user.id],
    (err) => {
      if (err) {
        console.error("Błąd zapytania SQL (UPDATE task_list):", err);
        return res.status(500).json({ error: "Błąd podczas edycji listy" });
      }
      res.json({ message: "Nazwa listy zaktualizowana" });
    }
  );
});

// Usuń listę i powiązane zadania oraz rekordy z list_users
app.delete("/task-lists/:id", authenticateToken, (req, res) => {
  const listId = req.params.id;

  // Krok 1: Usuń wszystkie zadania powiązane z listą
  db.query("DELETE FROM tasks WHERE list_id = ?", [listId], (err) => {
    if (err) {
      console.error("Błąd zapytania SQL (DELETE tasks):", err);
      return res.status(500).json({ error: "Błąd podczas usuwania zadań" });
    }

    // Krok 2: Usuń wszystkie rekordy z list_users powiązane z listą
    db.query("DELETE FROM list_users WHERE list_id = ?", [listId], (err) => {
      if (err) {
        console.error("Błąd zapytania SQL (DELETE list_users):", err);
        return res
          .status(500)
          .json({ error: "Błąd podczas usuwania powiązań listy" });
      }

      // Krok 3: Usuń samą listę
      db.query(
        "DELETE FROM task_lists WHERE id = ? AND created_by = ?",
        [listId, req.user.id],
        (err) => {
          if (err) {
            console.error("Błąd zapytania SQL (DELETE task_list):", err);
            return res
              .status(500)
              .json({ error: "Błąd podczas usuwania listy" });
          }
          res.json({ message: "Lista usunięta" });
        }
      );
    });
  });
});

// Pobierz wszystkie zadania dla danej listy
app.get("/tasks/:listId", authenticateToken, (req, res) => {
  const listId = req.params.listId;

  db.query(
    "SELECT t.*, u1.name AS created_by_name, u1.lastname AS created_by_lastname, u2.name AS assigned_to_name, u2.lastname AS assigned_to_lastname " +
      "FROM tasks t " +
      "JOIN users u1 ON t.created_by = u1.id " +
      "JOIN users u2 ON t.assigned_to = u2.id " +
      "JOIN task_lists tl ON t.list_id = tl.id " +
      "LEFT JOIN list_users lu ON tl.id = lu.list_id " +
      "WHERE t.list_id = ? AND (tl.created_by = ? OR lu.user_id = ?)",
    [listId, req.user.id, req.user.id],
    (err, results) => {
      if (err) {
        console.error("Błąd zapytania SQL (SELECT tasks):", err);
        return res.status(500).json({ error: "Błąd serwera" });
      }
      res.json(results);
    }
  );
});

// Dodaj nowe zadanie
app.post("/tasks", authenticateToken, (req, res) => {
  const { title, description, assigned_to, list_id, due_date, points } =
    req.body;
  const created_by = req.user.id;

  if (!title || !assigned_to || !list_id) {
    return res
      .status(400)
      .json({ error: "Tytuł, przypisany użytkownik i ID listy są wymagane" });
  }

  // Sprawdź, czy użytkownik assigned_to istnieje
  db.query(
    "SELECT id FROM users WHERE id = ?",
    [assigned_to],
    (err, results) => {
      if (err) {
        console.error("Błąd zapytania SQL (SELECT user):", err);
        return res.status(500).json({ error: "Błąd serwera" });
      }
      if (results.length === 0) {
        return res
          .status(400)
          .json({ error: "Przypisany użytkownik nie istnieje" });
      }

      db.query(
        "SELECT * FROM list_users WHERE list_id = ? AND user_id = ?",
        [list_id, assigned_to],
        (err, results) => {
          if (err) {
            console.error("Błąd zapytania SQL (SELECT list_users):", err);
            return res.status(500).json({ error: "Błąd serwera" });
          }

          if (results.length === 0) {
            db.query(
              "INSERT INTO list_users (list_id, user_id) VALUES (?, ?)",
              [list_id, assigned_to],
              (err) => {
                if (err) {
                  console.error("Błąd zapytania SQL (INSERT list_users):", err);
                  return res.status(500).json({ error: "Błąd serwera" });
                }
                insertTask();
              }
            );
          } else {
            insertTask();
          }
        }
      );
    }
  );

  function insertTask() {
    db.query(
      "INSERT INTO tasks (title, description, assigned_to, created_by, list_id, due_date, points) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [
        title,
        description,
        assigned_to,
        created_by,
        list_id,
        due_date || null,
        points || 0,
      ],
      (err) => {
        if (err) {
          console.error("Błąd zapytania SQL (INSERT task):", err);
          return res
            .status(500)
            .json({ error: "Błąd podczas dodawania zadania" });
        }
        res.status(201).json({ message: "Zadanie dodane" });
      }
    );
  }
});

// Aktualizuj zadanie
app.put("/tasks/:id", authenticateToken, (req, res) => {
  const taskId = req.params.id;
  const { title, description, status, assigned_to, due_date, points } =
    req.body;

  // Walidacja wymaganych pól
  if (!title || !assigned_to) {
    return res
      .status(400)
      .json({ error: "Tytuł i przypisany użytkownik są wymagane" });
  }

  // Sprawdź, czy użytkownik assigned_to istnieje
  db.query(
    "SELECT id FROM users WHERE id = ?",
    [assigned_to],
    (err, results) => {
      if (err) {
        console.error("Błąd zapytania SQL (SELECT user):", err);
        return res.status(500).json({ error: "Błąd serwera" });
      }
      if (results.length === 0) {
        return res
          .status(400)
          .json({ error: "Przypisany użytkownik nie istnieje" });
      }

      // Pobierz bieżący status i punkty zadania
      db.query(
        "SELECT status, points, assigned_to FROM tasks WHERE id = ?",
        [taskId],
        (err, results) => {
          if (err) {
            console.error("Błąd zapytania SQL (SELECT task):", err);
            return res.status(500).json({ error: "Błąd serwera" });
          }
          if (results.length === 0) {
            return res.status(404).json({ error: "Zadanie nie istnieje" });
          }

          const currentTask = results[0];
          const wasCompleted = currentTask.status === "completed";
          const isCompleted = status === "completed";
          const currentPoints = currentTask.points || 0;
          const newPoints = points || 0;
          const previousAssignedTo = currentTask.assigned_to;
          const newAssignedTo = assigned_to;

          // Wykonaj aktualizację zadania
          db.query(
            "UPDATE tasks SET title = ?, description = ?, status = ?, assigned_to = ?, due_date = ?, points = ? WHERE id = ?",
            [
              title,
              description,
              status,
              assigned_to,
              due_date || null,
              newPoints,
              taskId,
            ],
            (err) => {
              if (err) {
                console.error(
                  "Błąd zapytania SQL (UPDATE task):",
                  err.message,
                  err.sql
                );
                return res.status(500).json({
                  error: "Błąd podczas aktualizacji zadania",
                  details: err.message,
                });
              }

              // Aktualizuj punkty użytkownika
              if (!wasCompleted && isCompleted) {
                // Zadanie zmieniono na completed - dodaj punkty
                db.query(
                  "UPDATE users SET total_points = total_points + ? WHERE id = ?",
                  [newPoints, assigned_to],
                  (err) => {
                    if (err) {
                      console.error(
                        "Błąd zapytania SQL (UPDATE user points):",
                        err
                      );
                      return res
                        .status(500)
                        .json({ error: "Błąd podczas aktualizacji punktów" });
                    }
                    res.json({ message: "Zadanie zaktualizowane" });
                  }
                );
              } else if (wasCompleted && !isCompleted) {
                // Zadanie zmieniono z completed na pending - odejmij punkty
                db.query(
                  "UPDATE users SET total_points = total_points - ? WHERE id = ?",
                  [currentPoints, previousAssignedTo],
                  (err) => {
                    if (err) {
                      console.error(
                        "Błąd zapytania SQL (UPDATE user points):",
                        err
                      );
                      return res
                        .status(500)
                        .json({ error: "Błąd podczas aktualizacji punktów" });
                    }
                    res.json({ message: "Zadanie zaktualizowane" });
                  }
                );
              } else if (wasCompleted && newAssignedTo !== previousAssignedTo) {
                // Zmiana przypisanego użytkownika dla zadania completed - odejmij punkty staremu, dodaj nowemu
                db.query(
                  "UPDATE users SET total_points = total_points - ? WHERE id = ?",
                  [currentPoints, previousAssignedTo],
                  (err) => {
                    if (err) {
                      console.error(
                        "Błąd zapytania SQL (UPDATE user points - old):",
                        err
                      );
                      return res
                        .status(500)
                        .json({ error: "Błąd podczas aktualizacji punktów" });
                    }
                    db.query(
                      "UPDATE users SET total_points = total_points + ? WHERE id = ?",
                      [newPoints, newAssignedTo],
                      (err) => {
                        if (err) {
                          console.error(
                            "Błąd zapytania SQL (UPDATE user points - new):",
                            err
                          );
                          return res.status(500).json({
                            error: "Błąd podczas aktualizacji punktów",
                          });
                        }
                        res.json({ message: "Zadanie zaktualizowane" });
                      }
                    );
                  }
                );
              } else {
                res.json({ message: "Zadanie zaktualizowane" });
              }
            }
          );
        }
      );
    }
  );
});

// Usuń zadanie
app.delete("/tasks/:id", authenticateToken, (req, res) => {
  const taskId = req.params.id;

  // Pobierz informacje o zadaniu przed usunięciem
  db.query(
    "SELECT status, points, assigned_to FROM tasks WHERE id = ?",
    [taskId],
    (err, results) => {
      if (err) {
        console.error("Błąd zapytania SQL (SELECT task):", err);
        return res.status(500).json({ error: "Błąd serwera" });
      }
      if (results.length === 0) {
        return res.status(404).json({ error: "Zadanie nie istnieje" });
      }

      const task = results[0];
      if (task.status === "completed") {
        // Odejmij punkty użytkownikowi, jeśli zadanie było ukończone
        db.query(
          "UPDATE users SET total_points = total_points - ? WHERE id = ?",
          [task.points || 0, task.assigned_to],
          (err) => {
            if (err) {
              console.error("Błąd zapytania SQL (UPDATE user points):", err);
              return res
                .status(500)
                .json({ error: "Błąd podczas aktualizacji punktów" });
            }
            deleteTask();
          }
        );
      } else {
        deleteTask();
      }

      function deleteTask() {
        db.query("DELETE FROM tasks WHERE id = ?", [taskId], (err) => {
          if (err) {
            console.error("Błąd zapytania SQL (DELETE task):", err);
            return res
              .status(500)
              .json({ error: "Błąd podczas usuwania zadania" });
          }
          res.json({ message: "Zadanie usunięte" });
        });
      }
    }
  );
});

// Endpoint do debugowania czasu serwera
app.get("/time", (req, res) => {
  const serverTime = new Date();
  res.json({
    serverTime: serverTime.toISOString(),
    unixTimestamp: Math.floor(serverTime.getTime() / 1000),
  });
});

// Ustaw port z zmiennej środowiskowej (Railway ustawia PORT)
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));
