const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

console.log("JWT_SECRET:", process.env.JWT_SECRET);

// Konfiguracja CORS
const allowedOrigins = [
  "http://localhost:4200",
  "https://familyfront.vercel.app",
  // Dodaj inne domeny, jeśli testujesz na innych urządzeniach
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`Not allowed by CORS: ${origin}`));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true, // W razie potrzeby obsługi ciasteczek
  })
);

app.use(express.json());

// Połączenie z bazą danych
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Błąd połączenia z MySQL:", err);
    process.exit(1);
  }
  console.log("Połączono z MySQL");
});

// Middleware do weryfikacji tokena JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    console.log("Brak tokena w żądaniu:", req.url);
    return res.status(401).json({ error: "Brak tokena autoryzacji" });
  }

  console.log("Token otrzymany dla:", req.url, token);
  jwt.verify(
    token,
    process.env.JWT_SECRET,
    { clockTolerance: 300 },
    (err, user) => {
      if (err) {
        console.error("Błąd weryfikacji tokena:", err.message, req.url);
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
    const [results] = await db
      .promise()
      .query(
        "SELECT email, nickname FROM users WHERE email = ? OR nickname = ?",
        [email, nickname]
      );

    if (results.length > 0) {
      if (results.some((user) => user.email === email)) {
        return res.status(400).json({ error: "Email już istnieje" });
      }
      if (results.some((user) => user.nickname === nickname)) {
        return res.status(400).json({ error: "Nickname już istnieje" });
      }
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db
      .promise()
      .query(
        "INSERT INTO users (name, lastname, email, nickname, password, total_points) VALUES (?, ?, ?, ?, ?, ?)",
        [name, lastname, email, nickname, hashedPassword, 0]
      );

    res.status(201).json({ message: "Użytkownik zarejestrowany" });
  } catch (error) {
    console.error("Błąd rejestracji:", error);
    res.status(500).json({ error: "Błąd serwera", details: error.message });
  }
});

// Logowanie (Sign In)
app.post("/signin", async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: "Identyfikator i hasło są wymagane" });
  }

  try {
    const [results] = await db
      .promise()
      .query("SELECT * FROM users WHERE email = ? OR nickname = ?", [
        identifier,
        identifier,
      ]);

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
      { expiresIn: "2h" }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" } // Dłuższy czas ważności dla refresh tokena
    );

    res.json({
      token,
      refreshToken, // Zwracamy refresh token
      message: "Zalogowano pomyślnie",
    });
  } catch (error) {
    console.error("Błąd logowania:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// Nowy endpoint do odświeżania tokena
app.post("/refresh-token", (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    return res.status(401).json({ error: "Brak refresh tokena" });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const userId = decoded.id;

    // Sprawdź, czy użytkownik istnieje
    db.query(
      "SELECT id, email, name, lastname FROM users WHERE id = ?",
      [userId],
      (err, results) => {
        if (err) {
          console.error("Błąd zapytania SQL (SELECT user):", err);
          return res.status(500).json({ error: "Błąd serwera" });
        }
        if (results.length === 0) {
          return res.status(404).json({ error: "Użytkownik nie istnieje" });
        }

        const user = results[0];
        const newToken = jwt.sign(
          {
            id: user.id,
            email: user.email,
            name: user.name,
            lastname: user.lastname,
          },
          process.env.JWT_SECRET,
          { expiresIn: "2h" }
        );

        res.json({ token: newToken, message: "Token odświeżony" });
      }
    );
  } catch (error) {
    console.error("Błąd odświeżania tokena:", error.message);
    res
      .status(403)
      .json({ error: "Nieprawidłowy refresh token", details: error.message });
  }
});

// Pobierz wszystkich użytkowników
app.get("/users", authenticateToken, async (req, res) => {
  try {
    const [results] = await db
      .promise()
      .query("SELECT id, name, lastname, total_points FROM users");
    res.json(results);
  } catch (error) {
    console.error("Błąd pobierania użytkowników:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// Pobierz wszystkie listy zadań
app.get("/task-lists", authenticateToken, async (req, res) => {
  try {
    const [results] = await db
      .promise()
      .query(
        "SELECT DISTINCT tl.* FROM task_lists tl LEFT JOIN list_users lu ON tl.id = lu.list_id WHERE tl.created_by = ? OR lu.user_id = ?",
        [req.user.id, req.user.id]
      );
    res.json(results);
  } catch (error) {
    console.error("Błąd pobierania list zadań:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// Dodaj nową listę zadań
app.post("/task-lists", authenticateToken, async (req, res) => {
  const { name } = req.body;
  const created_by = req.user.id;

  if (!name) {
    return res.status(400).json({ error: "Nazwa listy jest wymagana" });
  }

  try {
    await db
      .promise()
      .query("INSERT INTO task_lists (name, created_by) VALUES (?, ?)", [
        name,
        created_by,
      ]);
    res.status(201).json({ message: "Lista dodana" });
  } catch (error) {
    console.error("Błąd dodawania listy zadań:", error);
    res.status(500).json({ error: "Błąd podczas dodawania listy" });
  }
});

// Edytuj nazwę listy
app.put("/task-lists/:id", authenticateToken, async (req, res) => {
  const listId = req.params.id;
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Nazwa listy jest wymagana" });
  }

  try {
    await db
      .promise()
      .query("UPDATE task_lists SET name = ? WHERE id = ? AND created_by = ?", [
        name,
        listId,
        req.user.id,
      ]);
    res.json({ message: "Nazwa listy zaktualizowana" });
  } catch (error) {
    console.error("Błąd aktualizacji listy zadań:", error);
    res.status(500).json({ error: "Błąd podczas edycji listy" });
  }
});

// Usuń listę i powiązane zadania oraz rekordy z list_users
app.delete("/task-lists/:id", authenticateToken, async (req, res) => {
  const listId = req.params.id;

  try {
    await db.promise().query("DELETE FROM tasks WHERE list_id = ?", [listId]);
    await db
      .promise()
      .query("DELETE FROM list_users WHERE list_id = ?", [listId]);
    await db
      .promise()
      .query("DELETE FROM task_lists WHERE id = ? AND created_by = ?", [
        listId,
        req.user.id,
      ]);
    res.json({ message: "Lista usunięta" });
  } catch (error) {
    console.error("Błąd usuwania listy zadań:", error);
    res.status(500).json({ error: "Błąd podczas usuwania listy" });
  }
});

// Pobierz wszystkie zadania dla danej listy
app.get("/tasks/:listId", authenticateToken, async (req, res) => {
  const listId = req.params.listId;

  try {
    const [results] = await db
      .promise()
      .query(
        "SELECT t.*, u1.name AS created_by_name, u1.lastname AS created_by_lastname, u2.name AS assigned_to_name, u2.lastname AS assigned_to_lastname " +
          "FROM tasks t JOIN users u1 ON t.created_by = u1.id JOIN users u2 ON t.assigned_to = u2.id " +
          "JOIN task_lists tl ON t.list_id = tl.id LEFT JOIN list_users lu ON tl.id = lu.list_id " +
          "WHERE t.list_id = ? AND (tl.created_by = ? OR lu.user_id = ?)",
        [listId, req.user.id, req.user.id]
      );
    res.json(results);
  } catch (error) {
    console.error("Błąd pobierania zadań:", error);
    res.status(500).json({ error: "Błąd serwera" });
  }
});

// Dodaj nowe zadanie
app.post("/tasks", authenticateToken, async (req, res) => {
  const { title, description, assigned_to, list_id, due_date, points } =
    req.body;
  const created_by = req.user.id;

  if (!title || !assigned_to || !list_id) {
    return res
      .status(400)
      .json({ error: "Tytuł, przypisany użytkownik i ID listy są wymagane" });
  }

  try {
    const [userResults] = await db
      .promise()
      .query("SELECT id FROM users WHERE id = ?", [assigned_to]);
    if (userResults.length === 0) {
      return res
        .status(400)
        .json({ error: "Przypisany użytkownik nie istnieje" });
    }

    const [listUserResults] = await db
      .promise()
      .query("SELECT * FROM list_users WHERE list_id = ? AND user_id = ?", [
        list_id,
        assigned_to,
      ]);

    if (listUserResults.length === 0) {
      await db
        .promise()
        .query("INSERT INTO list_users (list_id, user_id) VALUES (?, ?)", [
          list_id,
          assigned_to,
        ]);
    }

    await db
      .promise()
      .query(
        "INSERT INTO tasks (title, description, assigned_to, created_by, list_id, due_date, points) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
          title,
          description,
          assigned_to,
          created_by,
          list_id,
          due_date || null,
          points || 0,
        ]
      );

    res.status(201).json({ message: "Zadanie dodane" });
  } catch (error) {
    console.error("Błąd dodawania zadania:", error);
    res.status(500).json({ error: "Błąd podczas dodawania zadania" });
  }
});

// Aktualizuj zadanie
app.put("/tasks/:id", authenticateToken, async (req, res) => {
  const taskId = req.params.id;
  const { title, description, status, assigned_to, due_date, points } =
    req.body;

  if (!title || !assigned_to) {
    return res
      .status(400)
      .json({ error: "Tytuł i przypisany użytkownik są wymagane" });
  }

  try {
    const [userResults] = await db
      .promise()
      .query("SELECT id FROM users WHERE id = ?", [assigned_to]);
    if (userResults.length === 0) {
      return res
        .status(400)
        .json({ error: "Przypisany użytkownik nie istnieje" });
    }

    const [taskResults] = await db
      .promise()
      .query("SELECT status, points, assigned_to FROM tasks WHERE id = ?", [
        taskId,
      ]);
    if (taskResults.length === 0) {
      return res.status(404).json({ error: "Zadanie nie istnieje" });
    }

    const currentTask = taskResults[0];
    const wasCompleted = currentTask.status === "completed";
    const isCompleted = status === "completed";
    const currentPoints = currentTask.points || 0;
    const newPoints = points || 0;
    const previousAssignedTo = currentTask.assigned_to;
    const newAssignedTo = assigned_to;

    await db
      .promise()
      .query(
        "UPDATE tasks SET title = ?, description = ?, status = ?, assigned_to = ?, due_date = ?, points = ? WHERE id = ?",
        [
          title,
          description,
          status,
          assigned_to,
          due_date || null,
          newPoints,
          taskId,
        ]
      );

    if (!wasCompleted && isCompleted) {
      await db
        .promise()
        .query(
          "UPDATE users SET total_points = total_points + ? WHERE id = ?",
          [newPoints, assigned_to]
        );
    } else if (wasCompleted && !isCompleted) {
      await db
        .promise()
        .query(
          "UPDATE users SET total_points = total_points - ? WHERE id = ?",
          [currentPoints, previousAssignedTo]
        );
    } else if (wasCompleted && newAssignedTo !== previousAssignedTo) {
      await db
        .promise()
        .query(
          "UPDATE users SET total_points = total_points - ? WHERE id = ?",
          [currentPoints, previousAssignedTo]
        );
      await db
        .promise()
        .query(
          "UPDATE users SET total_points = total_points + ? WHERE id = ?",
          [newPoints, newAssignedTo]
        );
    }

    res.json({ message: "Zadanie zaktualizowane" });
  } catch (error) {
    console.error("Błąd aktualizacji zadania:", error);
    res.status(500).json({ error: "Błąd podczas aktualizacji zadania" });
  }
});

// Usuń zadanie
app.delete("/tasks/:id", authenticateToken, async (req, res) => {
  const taskId = req.params.id;

  try {
    const [taskResults] = await db
      .promise()
      .query("SELECT status, points, assigned_to FROM tasks WHERE id = ?", [
        taskId,
      ]);
    if (taskResults.length === 0) {
      return res.status(404).json({ error: "Zadanie nie istnieje" });
    }

    const task = taskResults[0];
    if (task.status === "completed") {
      await db
        .promise()
        .query(
          "UPDATE users SET total_points = total_points - ? WHERE id = ?",
          [task.points || 0, task.assigned_to]
        );
    }

    await db.promise().query("DELETE FROM tasks WHERE id = ?", [taskId]);
    res.json({ message: "Zadanie usunięte" });
  } catch (error) {
    console.error("Błąd usuwania zadania:", error);
    res.status(500).json({ error: "Błąd podczas usuwania zadania" });
  }
});

// Endpoint do debugowania czasu serwera
app.get("/time", (req, res) => {
  const serverTime = new Date();
  res.json({
    serverTime: serverTime.toISOString(),
    unixTimestamp: Math.floor(serverTime.getTime() / 1000),
  });
});

// Obsługa błędów globalnych
app.use((err, req, res, next) => {
  console.error("Globalny błąd:", err.message);
  res
    .status(500)
    .json({ error: "Wewnętrzny błąd serwera", details: err.message });
});

// Ustaw port z zmiennej środowiskowej
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serwer działa na porcie ${PORT}`));
