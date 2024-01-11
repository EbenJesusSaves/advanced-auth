import express from "express";
import { Low } from "lowdb";
import { JSONFile } from "lowdb/node";
import * as url from "url";
import bcrypt from "bcryptjs";
import * as jwtJsDecode from "jwt-js-decode";
import base64url from "base64url";
import SimpleWebAuthnServer from "@simplewebauthn/server";

const __dirname = url.fileURLToPath(new URL(".", import.meta.url));

const app = express();
app.use(express.json());

const adapter = new JSONFile(__dirname + "/auth.json");
const db = new Low(adapter);
await db.read();
db.data ||= { users: [] };

const rpID = "localhost";
const protocol = "http";
const port = 5050;
const expectedOrigin = `${protocol}://${rpID}:${port}`;

app.use(express.static("public"));
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

//checks if user already exist
function findUser(email) {
  const result = db.data.users.filter((u) => u.email === email);
  if (result.length === 0) return null;
  return result;
}

// ADD HERE THE REST OF THE ENDPOINTS
app.post("/auth/login/", (req, res) => {
  const userFound = findUser(res.body.email);
  if (bcrypt.compareSync(req.body.password, userFound.password)) {
    res.ok({ ok: true, name: userFound.name, email: userFound.email });
    userFound;
  } else {
    res.send({
      ok: false,
      message: "Wrong Credentials, Check email or password",
    });
  }
});

app.post("/auth/register", (req, res) => {
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(req.body.password, salt);

  const user = {
    name: req.body.name,
    email: req.body.email,
    password: hashedPassword,
  };
  const foundUser = findUser(user.email);
  if (foundUser) {
    //send error to client
    res.send({ ok: false, message: "User already exist" });
  } else {
    db.data.push(user);
    db.write();
  }
});

app.get("*", (req, res) => {
  res.sendFile(__dirname + "public/index.html");
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});
