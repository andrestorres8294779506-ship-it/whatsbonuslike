const express = require("express");
const session = require("express-session");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;
const MIN_WITHDRAW = 20;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "whatsbonus_secret",
  resave: false,
  saveUninitialized: true
}));

function loadUsers() {
  return JSON.parse(fs.readFileSync("users.json"));
}

function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

function loadWithdrawals() {
  return JSON.parse(fs.readFileSync("withdrawals.json"));
}

function saveWithdrawals(data) {
  fs.writeFileSync("withdrawals.json", JSON.stringify(data, null, 2));
}

// 🔐 Middleware para verificar login
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).send("No autorizado");
  }
  next();
}

// 🔐 Middleware para verificar admin
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Acceso solo para admin");
  }
  next();
}

app.use(express.static("public"));

// LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) return res.send("Credenciales incorrectas");

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return res.send("Credenciales incorrectas");

  req.session.user = user;
  res.redirect("/dashboard.html");
});

// DASHBOARD
app.get("/dashboard-data", requireLogin, (req, res) => {
  const users = loadUsers();
  const currentUser = users.find(u => u.username === req.session.user.username);
  res.json(currentUser);
});

// 💸 RETIRO
app.post("/withdraw", requireLogin, (req, res) => {
  let users = loadUsers();
  let withdrawals = loadWithdrawals();

  const user = users.find(u => u.username === req.session.user.username);

  if (user.bonus < MIN_WITHDRAW)
    return res.send("No tienes bonus suficiente");

  user.bonus -= MIN_WITHDRAW;

  withdrawals.push({
    id: crypto.randomBytes(4).toString("hex"),
    username: user.username,
    amount: MIN_WITHDRAW,
    date: new Date().toISOString(),
    status: "pendiente"
  });

  saveUsers(users);
  saveWithdrawals(withdrawals);

  res.send("Solicitud enviada");
});

// 👑 ADMIN - Ver retiros
app.get("/admin-withdrawals", requireAdmin, (req, res) => {
  res.json(loadWithdrawals());
});

// 👑 ADMIN - Aprobar
app.post("/approve/:id", requireAdmin, (req, res) => {
  let withdrawals = loadWithdrawals();
  const withdrawal = withdrawals.find(w => w.id === req.params.id);

  if (withdrawal) withdrawal.status = "aprobado";

  saveWithdrawals(withdrawals);
  res.send("Retiro aprobado");
});

// 👑 ADMIN - Rechazar
app.post("/reject/:id", requireAdmin, (req, res) => {
  let withdrawals = loadWithdrawals();
  let users = loadUsers();

  const withdrawal = withdrawals.find(w => w.id === req.params.id);

  if (withdrawal && withdrawal.status === "pendiente") {
    withdrawal.status = "rechazado";
    const user = users.find(u => u.username === withdrawal.username);
    if (user) user.bonus += withdrawal.amount;
  }

  saveUsers(users);
  saveWithdrawals(withdrawals);

  res.send("Retiro rechazado");
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login.html");
});

app.listen(PORT, () => {
  console.log("🔐 Sistema protegido activo en http://localhost:3000");
});