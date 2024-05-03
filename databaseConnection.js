require('dotenv').config();

const mongodb_cluster = process.env.MONGODB_CLUSTER;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

// making an instance of database client
const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_cluster}/?retryWrites=true`;
var database = new MongoClient(atlasURI, {useNewUrlParser: true, useUnifiedTopology: true});
  
module.exports = {database};