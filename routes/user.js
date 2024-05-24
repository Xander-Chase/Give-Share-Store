const express = require("express");
const Joi = require("joi");
const bcrypt = require("bcrypt");
const {userCollection} = require("../database/constants");
const router = express.Router();

router.get('/LogIn', (req, res) => {
    res.render("userLogIn");
});

router.get('/register', (req, res) => {
    res.render("userNewLogIn");
});

router.post('/LogInSubmit', async (req, res) => {

    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("userLogIn", { error: "Error: " + validationResult.error.message });
        return;
    }

    const user = await userCollection.findOne({ email: email });
    if (user === null) {
        console.log("User not found");
        res.render("userLogIn", { error: "Error: User not found" });
        return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        console.log("Invalid password");
        res.render("userLogIn", { error: "Error: Invalid password" });
        return;
    }

    req.session.loggedIn = true;
    req.session.isAdmin = false;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.password = user.password;
    console.log("user isLoggedIn:" + req.session.loggedIn);
    req.session.userId = user._id;
    res.redirect("/");
});


module.exports = router;