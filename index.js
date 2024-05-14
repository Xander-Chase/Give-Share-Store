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

// **************************** Functions ****************************
// Necessary functions to ensure non-repeating code.
// Fetches all the items from the product list
async function fetchAllItems()
{
    const productsColl = database.db(mongodb_database).collection('listing_items');
    return await productsColl.find().toArray(); // Fetch all items;
}

// creating a session
app.use(session({
    secret: node_session_secret,
    saveUninitialized: false,
    resave: true,
    store: mongoStore,
    cookie: { maxAge: 60 * 60 * 1000 * 10 }
}));

app.get('/', async (req, res) => {
    const isLoggedIn = req.session.loggedIn;
    let searchKey = "";
    let maximumPrice = 100000000;
    if (req.session.keyword != null)
        searchKey = req.session.keyword;

    if (req.session.maxPrice > 0)
        maximumPrice = req.session.maxPrice;

    try {

        let filtersHeader = ["Categories", "Price", "Sorting"];
        const productsCollection = database.db(mongodb_database).collection('listing_items');

        let prices = [];
        let currentListings = await productsCollection.find({ isFeatureItem: false,
            item_title: {$regex: searchKey, $options: 'i'}}).toArray();
        currentListings.forEach(function(item)
        {
            prices.push(item.item_price)
        });

        const sortedPrices = prices.sort(function(a, b) {
            if (a < b)
                return 1;
            else if (a > b)
                return -1;
            else
                return 0;
        });

        currentListings = await productsCollection.find({ isFeatureItem: false,
            item_title: {$regex: searchKey, $options: 'i'},
            item_price: {$lt: Math.round(maximumPrice)}}).toArray();

        let bodyFilters = getBodyFilters(sortedPrices[0], sortedPrices[prices.length-1], maximumPrice);

        res.render("landing", {isLoggedIn, currentListings, filterHeaders: filtersHeader, filterStuff: bodyFilters});
    } catch (error) {
        console.error('Failed to fetch current listings:', error);
        res.render("landing", {isLoggedIn, currentListings: []});
    }
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

function getBodyFilters(maxVal, minVal, currentPrice)
{
    return [

        "<ul class=\"list-group list-group-flush\">\n" +
        " <li class=\"list-group-item\">Home</li>" +
        " <li class=\"list-group-item\">Garden</li>\n" +
        " <li class=\"list-group-item\">Jewelry</li>\n" +
        " <li class=\"list-group-item\">Sports</li>\n" +
        " <li class=\"list-group-item\">Entertainment</li>\n" +
        " <li class=\"list-group-item\">Clothing</li>\n" +
        " <li class=\"list-group-item\">Accessories</li>\n" +
        " <li class=\"list-group-item\">Family</li>\n" +
        " <li class=\"list-group-item\">Electronics</li>\n" +
        " <li class=\"list-group-item\">Collectables</li>\n" +
        "</ul>",

        "<div class=\"row col-sm\">\n" +
        "        <div class=\"col text-start\">\n" +
        "            <label for=\"priceRange\" class=\"form-label\">" +
        "               <strong>$"+ (Math.floor(minVal / 5) * 5) + "</strong>" +
        "           </label>\n" +
        "        </div>\n" +
        "        <div class=\"col text-middle\">\n" +
        "            <label id=\"userRange\" for=\"priceRange\" class=\"form-label\">$" + currentPrice + "</label>\n" +
        "        </div>\n" +
        "        <div class=\"col text-end\">\n" +
        "            <label for=\"priceRange\" class=\"form-label\">" +
        "               <strong>$" + (Math.ceil(maxVal / 5) * 5) + "</strong>" +
        "           </label>\n" +
        "        </div>\n" +
        "        <input id=\"selectedPrice\" type=\"range\" class=\"form-range\" min="+ (Math.floor(minVal / 5) * 5) +" max="+ (Math.ceil(maxVal / 5) * 5) +" step=" +
        (Math.ceil(maxVal / 5) - (maxVal / 5)) + " id=\"priceRange\" oninput=\"" +
        "{document.getElementById('userRange').innerHTML = `$${this.value}`;}\">\n" +
        "</div>",

        "<ul class='list-group list-group-flush'>" +
        " <li class='list-group-item'>Sort by Highest Price</li>" +
        " <li class='list-group-item'>Sort by Lowest Price</li></ul>"
    ];
}
function sup()
{
    console.log("Wassup");

}
app.post('/keyword=', (req, res) => {
    req.session.keyword = null;
    res.redirect('/');
})
app.post('/keyword=:key', async (req, res) => {
    req.session.keyword = req.params.key;
    res.redirect('/');
});

app.post('/price=:newMax', (req, res) => {
    req.session.maxPrice = req.params.newMax;
    res.redirect('/');
})

app.post('/clearFilter', (req, res) =>
{
    req.session.maxPrice = 0;
    req.session.keyword = null;
    res.redirect('/');
})
// **************************** Requires Further Development ****************************
// Currently is passed all items in the database to the catalog view as proof of concept
// Will need to be updated to only pass items that were added to the cart
app.get('/cart', async (req, res) => {
    try {
        res.render('cartView', { items: await fetchAllItems() }); // Pass items to the EJS template
    } catch (error) {
        console.error('Failed to fetch items:', error);
        res.status(500).send('Error fetching items');
    }
});
app.get('/signout', (req, res) => {
    req.session.destroy()
    res.redirect('/');
});


app.get('/product-info/:id', async (req, res) => {
    try {
        const itemId = req.params.id;
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        
        const item = await productsCollection.findOne({ _id: new ObjectId(itemId) });

        if (!item) {
            res.status(404).send('Item not found');
            return;
        }

        const isLoggedIn = req.session.loggedIn;
        res.render('product-info', { item: item, isLoggedIn : isLoggedIn});
    } catch (error) {
        console.error('Failed to fetch item:', error);
        res.status(500).send('Error fetching item details');
    }
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
        res.redirect('/manage');
    } catch (error) {
        console.error('Error submitting new listing:', error);
        res.status(500).send('Failed to add new listing');
    }
});

app.get('/editListing/:id', async (req, res) => {
    const itemId = req.params.id;
    isLoggedIn = req.session.loggedIn;
    console.log("Received ID for editing:", itemId);

    if (!ObjectId.isValid(itemId)) {
        return res.status(400).send('Invalid ID format');
    }

    try {
        const listing = await database.db(mongodb_database).collection('listing_items').findOne({_id: new ObjectId(itemId)});
        if (!listing) {
            return res.status(404).send('Listing not found');
        }
        res.render('editListing', { listing, isLoggedIn});
    } catch (error) {
        console.error('Failed to fetch listing:', error);
        res.status(500).send('Error fetching listing details');
    }
});


app.post('/updateListing/:id', upload.none(), async (req, res) => {
    const itemId = new ObjectId(req.params.id);
    console.log("Form submission data:", req.body);

    const updateData = {
        item_title: req.body.item_title,
        item_price: parseFloat(req.body.item_price) || 0.00,
        item_quantity: parseInt(req.body.item_quantity) || 0,
        item_detailed_description: req.body.item_detailed_description || '',
        item_estimatedShippingCost: parseFloat(req.body.item_estimatedShippingCost) || 0.0,
        isFeatureItem: req.body.isFeatureItem ? req.body.isFeatureItem === 'true' : false,
    };


    try {
        const result = await database.db(mongodb_database).collection('listing_items').updateOne(
            { _id: itemId },
            { $set: updateData }
        );
        if (result.modifiedCount === 0) {
            console.log("No changes were made.");
            res.send("No changes were made.");
        } else {
            console.log("Updated listing successfully");
            res.redirect('/manage');
        }
    } catch (error) {
        console.error('Failed to update listing:', error);
        res.status(500).send('Error updating listing');
    }
});



app.get('/currentListings', async (req, res) => {
    try {
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const currentListings = await productsCollection.find({ isFeatureItem: false }).toArray();
        res.render('currentListings', { listings: currentListings });
    } catch (error) {
        console.error('Failed to fetch current listings:', error);
        res.status(500).send('Error fetching current listings');
        // handling error case - passing empty array
        res.render('currentListings', { listings: [] }); // rendering the page even in case of error with an empty array
    }
});


app.get('/previousListings', (req, res) => {
    res.render('previousListings');
});

app.get('/mailingList', (req, res) => {
    // Example data representing people on the mailing list
    const mailingList = [
        { name: "Alice Johnson", email: "alice.johnson@example.com" },
        { name: "Bob Smith", email: "bob.smith@example.com" },
        { name: "Carolyn B. Yates", email: "carolyn.yates@example.com" },
        { name: "David Gilmore", email: "david.gilmore@example.com" }
    ];

    res.render('mailingList', {
        people: mailingList,
        isLoggedIn: req.session.loggedIn
    });
});

app.get('/adminUsers', async (req, res) => {
    try {
        const admins = await adminCollection.find().toArray();
        res.render('adminUsers', { users: admins });
    } catch (error) {
        console.error('Error fetching admin users:', error);
        res.status(500).send('Error fetching admin users');
    }
});

app.post('/addUser', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await adminCollection.insertOne({ name, email, password: hashedPassword });
        //send a response to the client
        res.redirect('/manage');
    } catch (error) {
        console.error('Error adding new admin:', error);
        res.status(500).send('Failed to add new admin');
    }
});

app.get('/editUser/:id', async (req, res) => {
    try {
        const user = await adminCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!user) {
            res.status(404).send('User not found');
            return;
        }
        const isLoggedIn = req.session.loggedIn;
        res.render('editUser', { user, isLoggedIn : isLoggedIn});
    } catch (error) {
        console.error('Error retrieving user for editing:', error);
        res.status(500).send('Error retrieving user');
    }
});

app.post('/updateUser/:id', async (req, res) => {
    try {
        const { name, email } = req.body;
        await adminCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { name, email }}
        );
        res.redirect('/adminUsers');
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).send('Failed to update user');
    }
});

app.post('/deleteUser/:id', async (req, res) => {
    try {
        const result = await adminCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if(result.deletedCount === 1) {
            res.status(200).send('User deleted successfully');
        } else {
            res.status(404).send('User not found');
        }
    } catch (error) {
        console.error('Failed to delete user:', error);
        res.status(500).send('Failed to delete user');
    }
});



app.get('/featuredItems', async (req, res) => {
    try {
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const featuredItems = await productsCollection.find({ isFeatureItem: true }).toArray();
        res.render('featuredItems', { listings: featuredItems });
    } catch (error) {
        console.error('Failed to fetch featured items:', error);
        res.status(500).send('Error fetching featured items');
        res.render('featuredItems', { listings: [] });
    }
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