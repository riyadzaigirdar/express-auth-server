const express = require("express");
const bcrypt = require("bcrypt");

const app = express();

//Users
const users = [];

// middleware
app.use(express.json());
app.use(logger);

function logger(req, res, next) {
  console.log(`${req.protocol}://${req.hostname}${req.originalUrl}`);
  next();
}

// routes
app.get("/users", (req, res) => {
  res.json(users).status(200);
});

app.post("/users", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { username, password: hashedPassword };
    users.push(user);
    res.status(201).send("User Created");
  } catch {
    res.status(503).send("something went wrong");
  }
});

app.post("/users/login", async (req, res) => {
  const user = users.find((user) => user.username === req.body.username);

  if (!user) {
    return res.status(400).send("user not found");
  }
  try {
    const login = await bcrypt.compare(req.body.password, user.password);
    if (login) {
      res.status(200).send("logged in ");
    } else {
      res.status(403).send("not allowed");
    }
  } catch {
    res.status(503).send("something went wrong");
  }
});

app.listen(3000);
