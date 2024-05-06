require ('dotenv').config();                                // Import dotenv module to read ..env file
require ('./utils');                                        // Import utils.js file to define include function
const express = require('express');                         // Import express module to create server
const session = require('express-session');                 // Import express-session module to manage session
const MongoDBStore = require('connect-mongo');              // Import connect-mongo module to store session in MongoDB


const app = express();
app.set('view engine', 'ejs');                              // Set view engine to ejs

app.use(express.static('public'));                          // serve static image files
app.use(express.static('css'));                             // serve static css files
app.use(express.static('js'));                              // serve static js files

const port = process.env.PORT || 3000;                      // Set port to 8000 if not defined in ..env file

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
const userCollection = database.db(mongodb_database).collection('users');

// linking to mongoDb database
var mongoStore = MongoDBStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_cluster}/${mongodb_database}`,
    crypto: {
        secret: mongodb_session_secret
    },
    collection: 'sessions'
});

//printing status of database connection
database.connect().then(() => {
    console.log('MongoDB connected successfully');
}).catch((err) => {
    console.log('Error connecting to MongoDB', err);
});


app.get('/', (req, res) => {
    res.render("landing");
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
