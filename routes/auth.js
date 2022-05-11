
const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");


/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post('/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            throw new ExpressError("Username and password required", 400);
        }
        if (await User.authenticate(username, password)) {
            const token = jwt.sign({ username }, SECRET_KEY);
            User.updateLoginTimeStamp(username);
            return res.json({ message: 'Logged in!', token })
        } else {
            throw new ExpressError("Invalid credentials", 400)
        }
    }catch(err) {
        return next(err);
    }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

 router.post('/register', async (req, res, next) => {
    try {
        const { username, password, first_name, last_name, phone } = req.body;
        if (!username || !password) {
            throw new ExpressError("Username and password required", 400);
        }
        if (await User.register(username, password, first_name, last_name, phone)) {
            const token = jwt.sign({ username }, SECRET_KEY);
            User.updateLoginTimeStamp(username);
            return res.json({ message: 'Logged in!', token })
        } 
    }catch(err) {
        return next(err);
    }
});
module.exports = router;