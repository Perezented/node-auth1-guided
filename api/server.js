const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");
const reqAuth = require("../auth/req-auth");
const KnexSessionsStore = require("connect-session-knex")(session); //  install library
const usersRouter = require("../users/users-router.js");
const authRouter = require("../auth/authRouter");
const dbConnection = require("../database/connection");
const server = express();
const sessionConfig = {
    name: "monster",
    secret: process.env.SESSION_SECRET || "keep it secret, keep it safe!",
    cookie: {
        maxAge: 1000 * 600,
        secure: process.env.COOKIE_SECURE || false, //  true means only use over https //  true in production
        httpOnly: true, //JS code on the client cannot access the session cookie
    }, // 10 min in milliseconds
    resave: false,
    saveUninitialiezed: false, //  GDPR compliance
    store: new KnexSessionsStore({
        knex: dbConnection,
        sidfieldname: "sid",
        createtable: true,
        clearInterval: 6000, //  delete expired sessions - in milliseconds
    }),
};
server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.use("/api/users", reqAuth, usersRouter);
server.use("/api/auth", authRouter);

server.get("/", (req, res) => {
    res.json({ api: "up" });
});

module.exports = server;
