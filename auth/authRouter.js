const router = require("express").Router();
const bcryptjs = require("bcrypt");

const Users = require("../users/users-model");

router.post("/register", (req, res) => {
    const { username, password } = req.body;

    //  hash user password
    const rounds = process.env.HASH_ROUNDS || 8;
    const hash = bcryptjs.hashSync(password, rounds);
    Users.add({ username, password: hash })
        .then((users) => {
            res.status(200).json(users);
        })
        .catch((err) => res.send(err));
});

router.post("/login", (req, res) => {
    const { username, password } = req.body;

    //  verify user password
    Users.findBy({ username })
        .then(([user]) => {
            console.log(user);
            req.session.user = { user };
            if (user && bcryptjs.compareSync(password, user.password)) {
                res.status(200).json({ user, session: req.session });
            } else res.status(401).json({ message: "You cannot pass" });
        })
        .catch((err) => {
            // console.log(err);
            res.status(500).json(err);
        });
});

router.get("/logout", (req, res) => {
    if (req.session) {
        req.session.destroy((err) => {
            if (err) {
                console.log(err);
                res.status(500).json({
                    message: "could not log out, try again",
                });
            } else res.status(204).end();
        });
    } else {
        req.status(204).end();
    }
});
module.exports = router;
