const express = require("express");
const session = require("express-session");
const bodyParser = require("body-parser");
const persons = require("./data");
const { Sequelize } = require("sequelize");
const bcrypt = require("bcrypt");
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
require('dotenv').config();
app.use(express.static("public"));
app.set("view engine", "ejs");


app.use(
    session({
        secret: "tajni_kljuc",
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false }
    })
);

app.use( (req, res, next) => {
    let Cookie = "tajni Cookie";
    res.cookie('appSessionJS', Cookie, { httpOnly: false });
    next();
});

const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASSWORD, {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: process.env.DB_DIALECT,
    dialectOptions: {
        ssl: {
            require: process.env.DB_SSL_REQUIRE === "true",
            rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED === "false"
        }
    }
});


const User = require("./models/user")(sequelize);


async function initializeDatabase() {
    await sequelize.sync({ force: true });

    const hashedPasswordAdmin = await bcrypt.hash("adminpass", 10);

    await User.create({ username: "admin", password: hashedPasswordAdmin, role: "admin" });
    console.log("Korisnici su dodani u bazu.");
}

initializeDatabase().catch((error) => {
    console.error("Greška prilikom inicijalizacije baze:", error);
});


app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });

    if (user && await bcrypt.compare(password, user.password)) {
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.role = user.role;
        res.redirect("/");
    } else {
        res.status(403).send("Pogrešno korisničko ime ili lozinka");
    }
});


app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/"); // Vraća korisnika na početnu stranicu nakon odjave
    });
});


function sanitizeInput(input) {
    return input
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}


app.get("/", (req, res) => {
    res.render("index", {
        xssProtection: req.session.xssProtection || false,
        bacProtection: req.session.bacProtection || false,
        session: req.session
    });
});


app.get("/persons/:identifier", (req, res) => {
    const identifier = req.params.identifier;

    const useUUID = req.session.bacProtection;

    const person = useUUID
        ? persons.find(p => p.id === identifier)
        : persons[parseInt(identifier, 10)];

    if (!person) {
      return  res.render("not-found", {query: null});
    }

   return res.render("person", {
        query: identifier,
        person,
        bacProtection: req.session.bacProtection || false,
        session: req.session
    });
});


app.get("/persons", (req, res) => {
    req.session.xssProtection = req.query.xssProtection === "on";
    req.session.bacProtection = req.query.bacProtection === "on";

    let query = req.query.query || "";
    if (req.session.xssProtection) {
        query = sanitizeInput(query);
    }

    const personIndex = persons.findIndex(p => p.name.toLowerCase() === query.toLowerCase());
    const person = persons[personIndex];

    if (person) {
        const identifier = req.session.bacProtection ? person.id : personIndex;
      return  res.redirect(`/persons/${identifier}`);
    } else {
       return res.render("not-found", {query: query});
    }
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server radi na http://localhost:${PORT}`));



