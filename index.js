require ('dotenv').config();                                // Import dotenv module to read ..env file
require ('./utils');                                        // Import utils.js file to define include function
const express = require('express');                         // Import express module to create server
const session = require('express-session');                 // Import express-session module to manage session
const MongoDBStore = require('connect-mongo');              // Import connect-mongo module to store session in MongoDB
const Joi = require('joi');                                 // include the joi module
const bcrypt = require('bcrypt');                           // include the bcrypt module
const { ObjectId } = require('mongodb');                    // include the ObjectId module
const { MongoClient} = require('mongodb');                  // include the MongoClient modules
const AWS = require('aws-sdk');                             // include the AWS module
const multer = require('multer');                           // include the multer module
const multerS3 = require('multer-s3');                      // include the multer-s3 module
const { S3Client } = require("@aws-sdk/client-s3");         // include the S3Client module
const { Upload } = require("@aws-sdk/lib-storage");         // include the Upload module




const app = express();
app.set('view engine', 'ejs');                              // Set view engine to ejs

app.use(express.urlencoded({ extended: true }));            // parse urlencoded request bodies
app.use(express.static('public'));                          // serve static image files
app.use(express.static('css'));                             // serve static css files
app.use(express.static('js'));                              // serve static js files
app.use(express.json());                                    // parse json request bodies

const port = process.env.PORT || 5000;                      // Set port to 8000 if not defined in ..env file


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
    res.redirect("/");
});

app.post('/search', (req, res) => {
    res.render('catalog');
});

// **************************** Requires Further Development ****************************
// Currently is passed all items in the database to the catalog view as proof of concept
// Will need to be updated to only pass items that were added to the cart
app.get('/cart', async (req, res) => {
    try {
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const productList = await productsCollection.find({}).toArray(); // Fetch all items
        res.render('cartView', { items: productList }); // Pass items to the EJS template
    } catch (error) {
        console.error('Failed to fetch items:', error);
        res.status(500).send('Error fetching items');
    }
});
app.get('/signout', (req, res) => {
    req.session.destroy()
    res.redirect('/');
});

app.get('/product-info', (req, res) => {
    const isLoggedIn = req.session.loggedIn;
    res.render("product-info", {isLoggedIn : isLoggedIn});
});

app.get('/about', (req, res) => {
    const isLoggedIn = req.session.loggedIn; 
    res.render("about", {isLoggedIn : isLoggedIn});
});

app.get('/contact-us', (req, res) => {
    const isLoggedIn = req.session.loggedIn; 
    res.render("contact", {isLoggedIn : isLoggedIn});
});

app.get('/manage', (req, res) => {
    if (req.session.loggedIn) {
        const isLoggedIn = req.session.loggedIn;
        res.render("product-management", {isLoggedIn : isLoggedIn});
    } 
    else {
        res.redirect('/adminLogIn');
    }
});


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
        bucket: 'the-vintage-garage-test',
        metadata: function (req, file, cb) {
            cb(null, {fieldName: file.fieldname});
        },
        key: function (req, file, cb) {
            const folder = file.mimetype.startsWith('image/') ? 'images/' : 'videos/';
            cb(null, folder + Date.now().toString() + '-' + file.originalname);
        }
    })
});


// ------------------ multer END ------------------

// // ------------------ AWS Test Start ------------------
// const { PutObjectCommand } = require("@aws-sdk/client-s3");

// async function testUpload() {
//     try {
//         const data = await s3.send(new PutObjectCommand({
//             Bucket: "the-vintage-garage-test",
//             Key: "test-upload.txt",
//             Body: "Hello World!"
//         }));
//         console.log("Success", data);
//     } catch (err) {
//         console.error("Error", err);
//     }
// }
// testUpload();

// // ------------------ AWS Test End ------------------

app.get('/addListing', (req, res) => {
    res.render('addListing');
});

// Route to handle form submission
app.post('/submitListing', upload.fields([{ name: 'photo', maxCount: 10 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    const photos = req.files['photo'] ? req.files['photo'].map(file => file.location) : [];
    const videos = req.files['video'] ? req.files['video'].map(file => file.location) : [];

    const listingItemsCollection = database.db(mongodb_database).collection('listing_items');
    const document = {
        product_img_URL: photos,
        product_video_URL: videos,
        item_title: req.body.item_title,
        item_price: parseFloat(req.body.item_price) || 0.00,
        item_quantity: parseInt(req.body.item_quantity) || 0,
        item_detailed_description: req.body.item_detailed_description || '',
        item_estimatedShippingCost: parseFloat(req.body.item_estimatedShippingCost) || 0.0,
        isFeatureItem: req.body.isFeatureItem === 'true',
        item_category: Array.isArray(req.body.item_category) ? req.body.item_category : [req.body.item_category]
    };

    try {
        await listingItemsCollection.insertOne(document);
        res.send('Listing added successfully!');
    } catch (error) {
        console.error('Error submitting new listing:', error);
        res.status(500).send('Failed to add new listing');
    }
});

app.get('/currentListings', (req, res) => {
    res.render('currentListings');
});

app.get('/previousListings', (req, res) => {
    res.render('previousListings');
});

app.get('/mailingList', (req, res) => {
    res.render('mailingList');
});

app.get('/featuredItems', (req, res) => {
    res.render('featuredItems');
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

// ----------------- Stripe Payment START -----------------

app.get('/StripeSuccess', (req, res) => {
    res.render('StripeSuccess');
});

app.get('/StripeCancel', (req, res) => {
    res.render('StripeCancel');
});

// Stripe test secret API key.
const stripe = require('stripe')('sk_test_51OZSVHAcq23T9yD7gpE3kQS73T5AnO6UEaecXMwkzvGc9hVh1QlPNFmM3rzI9cxJ2tU2FtUAPzvcSc1obqPcrUfZ00PojCiOni');

app.use(express.static('public'));

const YOUR_DOMAIN = 'http://localhost:8000';

// Endpoint to create a Stripe checkout session
app.post('/create-checkout-session', async (req, res) => {
    try {
        // Extract product IDs from the POST data
        const itemIds = req.body.productIds;
        if (!itemIds || !Array.isArray(itemIds)) {
            throw new Error('Product IDs not received or not in array format');
        }

        // Fetch product details from MongoDB
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const items = await productsCollection.find({
            '_id': { $in: itemIds.map(id => ObjectId.createFromHexString(id)) } // Convert string IDs to ObjectId instances
        }).toArray();

        // Prepare line items for the Stripe session
        const line_items = items.map(item => ({
            price_data: {
                currency: 'cad',
                product_data: {
                    name: item.item_title,
                    images: [item.product_img_URL[0]]
                },
                unit_amount: Math.round(item.item_price * 100), // Convert price to cents
            },
            quantity: parseInt(item.item_quantity),
        }));

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items,
            mode: 'payment',
            success_url: `${YOUR_DOMAIN}/StripeSuccess`,
            cancel_url: `${YOUR_DOMAIN}/StripeCancel`,
        });

        // Redirect the client to the Stripe checkout
        res.redirect(303, session.url);
    } catch (error) {
        console.error('Failed to create checkout session:', error);
        res.status(500).send('Error creating checkout session: ' + error.message);
    }
});

// ----------------- Stripe Payment END -----------------