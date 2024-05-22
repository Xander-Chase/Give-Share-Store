const {database} = include('databaseConnection');
const {MONGODB_DATABASE}= require('../.env')

const adminCollection = database.db(MONGODB_DATABASE).collection('admins');
const userCollection = database.db(MONGODB_DATABASE).collection('users');
const categoryCollection = database.db(MONGODB_DATABASE).collection('categories');

module.exports =
    {
        adminCollection,
        userCollection,
        categoryCollection
    }
