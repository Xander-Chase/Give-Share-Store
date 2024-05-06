require ('dotenv').config();                                // Import dotenv module to read ..env file
require ('./utils');                                        // Import utils.js file to define include function
const express = require('express');                         // Import express module to create server
const session = require('express-session');                 // Import express-session module to manage session
const MongoDBStore = require('connect-mongo');              // Import connect-mongo module to store session in MongoDB
const Joi = require('joi');                                 // include the joi module
const bcrypt = require('bcrypt');                           // include the bcrypt module




const app = express();
app.set('view engine', 'ejs');                              // Set view engine to ejs

app.use(express.urlencoded({ extended: false }));           // parse urlencoded request bodies
app.use(express.static('public'));                          // serve static image files
app.use(express.static('css'));                             // serve static css files
app.use(express.static('js'));                              // serve static js files
app.use(express.json());                                    // parse json request bodies

const port = process.env.PORT || 8000;                      // Set port to 8000 if not defined in ..env file

// secret variables located in ..env file
const mongodb_cluster = process.env.MONGODB_CLUSTER;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// importing the database object from databaseConnection.js file
var { database } = include('databaseConnection');

// referencing to users collection in database
const adminCollection = database.db(mongodb_database).collection('admins');

// linking to mongoDb database
var mongoStore = MongoDBStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_cluster}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    },
    collection: 'sessions'
});

// creating a session
app.use(session({
    secret: node_session_secret,
    saveUninitialized: false,
    resave: true,
    store: mongoStore,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

app.get('/', (req, res) => {
    const isLoggedIn = req.session.loggedIn; 
    res.render("landing" , {isLoggedIn : isLoggedIn});
});

async function hashExistingPasswords() {
    try {
        const admins = adminCollection;
        const cursor = await admins.find({});

        await cursor.forEach(async (admin) => {
            if (admin.password && admin.password.length < 60) {                                                     // assuming bcrypt hashes are 60 chars long
                const hashedPassword = await bcrypt.hash(admin.password, 10);                                       // hash the plaintext password
                const result = await admins.updateOne({ _id: admin._id }, { $set: { password: hashedPassword } });
                console.log(`Updated password for admin ${admin.email}: ${result.modifiedCount}`);
            }
        });
        console.log("All passwords have been hashed and updated.");
    } catch (err) {
        console.error('Error updating passwords:', err);
    }
}

app.get("/loginPortal", (req, res) => {
    res.render('loginPortal');
})

app.get('/adminLogIn', (req, res) => {
    res.render("adminLogIn");
});

app.post('/adminLogInSubmit', async (req, res) => {

    console.log("Admin Log In Submit")

    const email = req.body.email;
    const password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render("adminLogIn", {error: "Error: "+validationResult.error.message});
        return;
    }

    const user = await adminCollection.findOne({ email: email });
    if (user === null) {
        console.log("User not found");
        res.render("adminLogIn", {error: "Error: User not found"});
        return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        console.log("Invalid password");
        res.render("adminLogIn", {error: "Error: Invalid password"});
        return;
    }

    req.session.loggedIn = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.password = user.password;
    console.log(req.session.password);
    res.redirect("/");

});

app.get('/signout', (req, res) => {
    req.session.destroy()
    res.redirect('/');
});

// connect to the database and hash passwords if necessary, then start the server
database.connect().then(async () => {
    console.log('MongoDB connected successfully');
    await hashExistingPasswords();  // ensure all passwords are hashed before starting the server
    app.listen(port, () => {
        console.log(`Server is running on port ${port}`);
    });
}).catch((err) => {
    console.log('Error connecting to MongoDB', err);
});

