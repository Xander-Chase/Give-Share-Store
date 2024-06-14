// Set up variables + imports
require('dotenv').config();                                    // Import dotenv module to read ..env file
const AWS = require('aws-sdk');                                 // include the AWS module
const multer = require('multer');                               // include the multer module
const multerS3 = require('multer-s3');                          // include the multer-s3 module
const { S3Client, DeleteObjectCommand } = require("@aws-sdk/client-s3");             // include the S3Client module
const { Upload } = require("@aws-sdk/lib-storage");             // include the Upload module

// ------------------ AWS S3 START ------------------

// Configures AWS to use .env credentials and region
const s3 = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});

// ------------------ AWS S3 END ------------------

// ------------------ multer START ------------------

const upload = multer({
    storage: multerS3({
        s3: s3,
        bucket: process.env.AWS_BUCKET_NAME,
        metadata: function (req, file, cb) {
            cb(null, {fieldName: file.fieldname});
        },
        key: function (req, file, cb) {
            const folder = file.mimetype.startsWith('image/') ? 'images/' : 'videos/';
            cb(null, folder + Date.now().toString() + '-' + file.originalname);
        }
    })
});

const featureVideoUpload = multer({
    storage: multerS3({
        s3: s3,
        bucket: process.env.AWS_BUCKET_NAME,
        metadata: function (req, file, cb) {
            cb(null, {fieldName: file.fieldname});
        },
        key: function (req, file, cb) {
            const folder = 'videos/';
            cb(null, folder + Date.now().toString() + '-' + file.originalname);
        }
    })
});

// ------------------ multer END ------------------


// Function to delete a file from S3
async function deleteFromS3(url) {
    const bucketName = process.env.AWS_BUCKET_NAME;
    const key = url.split('.com/')[1];

    const deleteParams = {
        Bucket: process.env.AWS_BUCKET_NAME,
        Key: key
    };

    try {
        const data = await s3.send(new DeleteObjectCommand(deleteParams));
        console.log(`File deleted successfully from S3: ${url}`);
    } catch (err) {
        console.error(`Error deleting file from S3: ${url}`, err);
    }
}

// Exports variables + functions
module.exports =
{
    s3,
    upload,
    featureVideoUpload,
    deleteFromS3
}