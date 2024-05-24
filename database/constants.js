// Set up variables + imports
require('dotenv').config();
var {database} = include('databaseConnection');

const mongo_db = process.env.MONGODB_DATABASE;

// Set up collections
const adminCollection = database.db(mongo_db).collection('admins');
const userCollection = database.db(mongo_db).collection('users');
const categoryCollection = database.db(mongo_db).collection('categories');

// Exports collection and database.
module.exports =
    {
        adminCollection,
        userCollection,
        categoryCollection,
        database
    }
