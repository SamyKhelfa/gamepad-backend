const express = require("express");
const app = express();
const port = 3000;
const SHA256 = require("crypto-js/sha256");
const encBase64 = require("crypto-js/enc-base64");
const uid2 = require("uid2");
const mongoose = require("mongoose");
const cors = require("cors");

app.use(express.json());
app.use(cors());

mongoose.connect("mongodb://127.0.0.1/Users", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = mongoose.model("User", {
  email: String,
  username: String,
  hash: String,
  salt: String,
  token: String,
});

app.post("/signup", async (req, res) => {
  try {
    const { email, username, password, file } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ message: "Cet e-mail est déjà utilisé." });
    }

    const salt = uid2(16);
    const hashedPassword = SHA256(password + salt).toString(encBase64);

    const token = uid2(16);

    const newUser = new User({
      email,
      username,
      file,
      hash: hashedPassword,
      salt,
      token,
    });

    await newUser.save();

    res.status(201).json({ message: "Inscription réussie !", user: newUser });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de l'inscription." });
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (user) {
      // Vérifiez si le mot de passe correspond
      const hashedPassword = SHA256(req.body.password + user.salt).toString(
        encBase64
      );

      if (hashedPassword === user.hash) {
        // Génération d'un nouveau token
        const token = uid2(16);
        user.token = token;
        await user.save();

        res.status(200).json({
          _id: user._id,
          token: user.token,
          username: user.username, // Vous pouvez inclure d'autres informations de l'utilisateur si nécessaire
        });
      } else {
        res.status(401).json({ message: "Mot de passe incorrect." });
      }
    } else {
      res.status(400).json({ message: "Utilisateur non trouvé." });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Erreur lors de la connexion." });
  }
});

// Exemple de middleware pour vérifier l'authentification à chaque requête
function authenticateUser(req, res, next) {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: "Accès non autorisé." });
  }

  // Vérifier le token dans la base de données
  User.findOne({ token }, (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: "Accès non autorisé." });
    }

    // Authentification réussie
    req.user = user;
    next();
  });
}

app.get("/profile", authenticateUser, (req, res) => {
  // La requête est autorisée car l'utilisateur est authentifié
  res.json({ user: req.user });
});

app.listen(port, () => {
  console.log(`Serveur en cours d'exécution sur le port ${port}`);
});
