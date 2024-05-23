require('dotenv').config();
var {database} = include('databaseConnection');

const mongo_db = process.env.MONGODB_DATABASE;

const adminCollection = database.db(mongo_db).collection('admins');
const userCollection = database.db(mongo_db).collection('users');
const categoryCollection = database.db(mongo_db).collection('categories');

module.exports =
    {
        adminCollection,
        userCollection,
        categoryCollection,
        database
    }
