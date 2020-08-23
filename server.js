require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

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

function authenticateUser(req, res, next) {
  const authorization = req.headers["authorization"];
  const token = authorization && authorization.split(" ")[1];
  if (!token) {
    next();
  } else {
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      if (err) {
        return res.status(403).send();
      }
      console.log(user);
      req.user = user;
      next();
    });
  }
}
let refreshTokens = [];
const posts = [
  {
    id: 1,
    name: "riyad",
    title: "post 1 title",
  },
  {
    id: 2,
    name: "ammu",
    title: "post 2 title",
  },
];
// routes
app.get("/posts", authenticateUser, (req, res) => {
  if (req.user) {
    const filteredPosts = posts.filter(
      (post) => post.name === req.user.username
    );
    res.json(filteredPosts).status(200);
  } else {
    res.json(posts).status(200);
  }
});

app.get("/users", (req, res) => {
  res.json(users).status(200);
});

app.get("/token", (req, res) => {
  const refreshToken = req.body["refreshToken"];

  if (refreshTokens.includes(refreshToken)) {
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if (err) {
        return res.status(503).send();
      }
      const accessToken2 = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "20sec",
      });
      const refreshToken2 = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      res.json({ accessToken: accessToken2, refreshToken: refreshToken2 });
    });
    refreshTokens = refreshTokens.filter((token) => token != refreshToken);
  } else {
    res.status(403).send();
  }
});

app.get("/logout", (req, res) => {
  const refreshToken = req.body["refreshToken"];
  refreshTokens = refreshTokens.filter((token) => token != refreshToken);
  res.status(200).send();
});

app.post("/users/signin", async (req, res) => {
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
      const accessToken = jwt.sign(
        { username: user.username },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "20sec" }
      );
      console.log(accessToken);
      const refreshToken = jwt.sign(
        { username: user.username },
        process.env.REFRESH_TOKEN_SECRET
      );
      refreshTokens.push(refreshToken);
      res.json({ accessToken, refreshToken });
    } else {
      res.status(403).send("not allowed");
    }
  } catch {
    res.status(503).send("something went wrong");
  }
});

app.listen(3000);
