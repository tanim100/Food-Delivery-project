const express = require("express");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const SECRET = "tanim-food-delivery-secret-2026";

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const ORDERS_FILE = path.join(DATA_DIR, "orders.json");

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");
if (!fs.existsSync(ORDERS_FILE)) fs.writeFileSync(ORDERS_FILE, "[]");

const foods = [
  { id: 1, name: "Chicken Burger", price: 220, category: "Burger", emoji: "🍔", desc: "Juicy chicken patty with cheese and fresh vegetables." },
  { id: 2, name: "Beef Burger", price: 280, category: "Burger", emoji: "🍔", desc: "Premium beef patty, cheese, lettuce and special sauce." },
  { id: 3, name: "Chicken Pizza", price: 650, category: "Pizza", emoji: "🍕", desc: "Loaded chicken pizza with mozzarella and herbs." },
  { id: 4, name: "Beef Pizza", price: 720, category: "Pizza", emoji: "🍕", desc: "Beef, capsicum, onion and extra cheese." },
  { id: 5, name: "Fried Chicken", price: 320, category: "Chicken", emoji: "🍗", desc: "Crispy fried chicken with our signature seasoning." },
  { id: 6, name: "Chicken Biryani", price: 190, category: "Rice", emoji: "🍛", desc: "Aromatic basmati rice with tender chicken." },
  { id: 7, name: "Beef Tehari", price: 210, category: "Rice", emoji: "🍚", desc: "Traditional Bangladeshi beef tehari." },
  { id: 8, name: "French Fries", price: 120, category: "Snacks", emoji: "🍟", desc: "Golden crispy fries with seasoning." },
  { id: 9, name: "Cold Coffee", price: 160, category: "Drinks", emoji: "🥤", desc: "Creamy chilled coffee with a smooth finish." },
  { id: 10, name: "Chocolate Cake", price: 180, category: "Dessert", emoji: "🍰", desc: "Soft chocolate cake with rich chocolate frosting." }
];

function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function createToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: "Login required." });

  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Session expired. Please login again." });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required." });
  }
  next();
}

function seedAdmin() {
  const users = readJSON(USERS_FILE);
  const exists = users.some(u => u.username.toLowerCase() === "tanim");
  if (!exists) {
    users.push({
      id: Date.now(),
      username: "Tanim",
      password: bcrypt.hashSync("Tanim@100", 10),
      name: "Shahoriar Tanim",
      email: "admin@tanimfood.com",
      phone: "01XXXXXXXXX",
      address: "Dhaka, Bangladesh",
      role: "admin",
      createdAt: new Date().toISOString()
    });
    writeJSON(USERS_FILE, users);
  }
}
seedAdmin();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/api/foods", (req, res) => {
  res.json(foods);
});

app.post("/api/register", async (req, res) => {
  const { username, password, name, email, phone, address } = req.body;

  if (!username || !password || !name || !email || !phone || !address) {
    return res.status(400).json({ message: "সব ঘর পূরণ করুন!" });
  }

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ message: "Username কমপক্ষে 3 এবং Password কমপক্ষে 6 অক্ষরের হতে হবে।" });
  }

  const users = readJSON(USERS_FILE);
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ message: "এই Username আগে থেকেই আছে!" });
  }

  const user = {
    id: Date.now(),
    username,
    password: await bcrypt.hash(password, 10),
    name,
    email,
    phone,
    address,
    role: "user",
    createdAt: new Date().toISOString()
  };

  users.push(user);
  writeJSON(USERS_FILE, users);

  res.status(201).json({ message: "Account তৈরি হয়েছে! এখন Login করুন।" });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.username.toLowerCase() === String(username || "").toLowerCase());

  if (!user || !(await bcrypt.compare(password || "", user.password))) {
    return res.status(401).json({ message: "Username অথবা Password ভুল হয়েছে!" });
  }

  const token = createToken(user);
  const safeUser = {
    id: user.id,
    username: user.username,
    name: user.name,
    email: user.email,
    phone: user.phone,
    address: user.address,
    role: user.role
  };

  res.json({ message: "Login successful!", token, user: safeUser });
});

app.get("/api/me", auth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: "User not found." });

  res.json({
    id: user.id,
    username: user.username,
    name: user.name,
    email: user.email,
    phone: user.phone,
    address: user.address,
    role: user.role
  });
});

app.put("/api/me", auth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const index = users.findIndex(u => u.id === req.user.id);
  if (index === -1) return res.status(404).json({ message: "User not found." });

  const { name, email, phone, address } = req.body;
  users[index] = { ...users[index], name, email, phone, address };
  writeJSON(USERS_FILE, users);

  res.json({ message: "Profile updated successfully." });
});

app.post("/api/orders", auth, (req, res) => {
  const { items, paymentMethod, deliveryAddress, phone, note } = req.body;

  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ message: "Cart is empty!" });
  }

  if (!["Cash on Delivery", "bKash", "Nagad"].includes(paymentMethod)) {
    return res.status(400).json({ message: "Invalid payment method." });
  }

  const validItems = items.map(item => {
    const food = foods.find(f => f.id === Number(item.id));
    if (!food) return null;

    const qty = Math.max(1, Math.min(20, Number(item.quantity) || 1));
    return {
      id: food.id,
      name: food.name,
      price: food.price,
      quantity: qty,
      subtotal: food.price * qty
    };
  }).filter(Boolean);

  if (!validItems.length) return res.status(400).json({ message: "No valid food item found." });

  const subtotal = validItems.reduce((sum, item) => sum + item.subtotal, 0);
  const deliveryFee = subtotal >= 800 ? 0 : 60;
  const total = subtotal + deliveryFee;

  const orders = readJSON(ORDERS_FILE);
  const order = {
    id: "FD-" + Date.now(),
    userId: req.user.id,
    username: req.user.username,
    items: validItems,
    subtotal,
    deliveryFee,
    total,
    paymentMethod,
    deliveryAddress,
    phone,
    note: note || "",
    status: "Pending",
    createdAt: new Date().toISOString()
  };

  orders.push(order);
  writeJSON(ORDERS_FILE, orders);

  res.status(201).json({ message: "Order placed successfully!", order });
});

app.get("/api/orders", auth, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  const mine = orders
    .filter(o => o.userId === req.user.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json(mine);
});

app.get("/api/admin/orders", auth, adminOnly, (req, res) => {
  const orders = readJSON(ORDERS_FILE);
  res.json(orders.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

app.put("/api/admin/orders/:id", auth, adminOnly, (req, res) => {
  const allowed = ["Pending", "Confirmed", "Preparing", "Out for Delivery", "Delivered", "Cancelled"];
  const { status } = req.body;

  if (!allowed.includes(status)) {
    return res.status(400).json({ message: "Invalid order status." });
  }

  const orders = readJSON(ORDERS_FILE);
  const index = orders.findIndex(o => o.id === req.params.id);
  if (index === -1) return res.status(404).json({ message: "Order not found." });

  orders[index].status = status;
  orders[index].updatedAt = new Date().toISOString();
  writeJSON(ORDERS_FILE, orders);

  res.json({ message: "Order status updated." });
});

app.get("/api/admin/users", auth, adminOnly, (req, res) => {
  const users = readJSON(USERS_FILE).map(({ password, ...user }) => user);
  res.json(users);
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Tanim Food Delivery running at http://localhost:${PORT}`);
});
