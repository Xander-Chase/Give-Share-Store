require('dotenv').config();                                    // Import dotenv module to read ..env file
require('./utils');                                            // Import utils.js file to define include function
const express = require('express');                             // Import express module to create server
const session = require('express-session');                     // Import express-session module to manage session
const MongoDBStore = require('connect-mongo');                  // Import connect-mongo module to store session in MongoDB
const Joi = require('joi');                                     // include the joi module
const bcrypt = require('bcrypt');                               // include the bcrypt module
const { ObjectId } = require('mongodb');                        // include the ObjectId module
const { MongoClient } = require('mongodb');                      // include the MongoClient modules
const AWS = require('aws-sdk');                                 // include the AWS module
const multer = require('multer');                               // include the multer module
const multerS3 = require('multer-s3');                          // include the multer-s3 module
const { S3Client, DeleteObjectCommand } = require("@aws-sdk/client-s3");             // include the S3Client module
const { Upload } = require("@aws-sdk/lib-storage");             // include the Upload module
const Realm = require("realm");                                 // Import Realm module to interact with MongoDB Realm
const { google } = require("googleapis");                       // Import googleapis module to interact with Google APIs
const fetch = import('node-fetch');                             // Import node-fetch module to fetch data from API
const mailchimp = require('@mailchimp/mailchimp_marketing');    // Import mailchimp_marketing module to interact with Mailchimp API
const formData = require('form-data');                      // Import form-data module to handle form data
const Mailgun = require('mailgun.js');                      // Import mailgun.js module to send email
const {RecaptchaEnterpriseServiceClient} = require('@google-cloud/recaptcha-enterprise'); // Import recaptcha-enterprise module to interact with Google Recaptcha Enterprise API
const bodyParser = require('body-parser');


const app = express();
const routes = require('./routes');

const { getBodyFilters, getCategoriesNav } = require('./controller/htmlContent');
app.set('view engine', 'ejs');                              // Set view engine to ejs

app.use(express.urlencoded({ extended: true }));            // parse urlencoded request bodies
app.use(express.static('public'));                          // serve static image files
app.use(express.static('css'));                             // serve static css files
app.use(express.static('js'));                              // serve static js files
app.use(express.json());                                    // parse json request bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


const searchRoute = require('./routes/filter');
const adminRoute = require('./routes/admin');
const cartRoute = require('./routes/cart');



const port = process.env.PORT || 5000;                      // Set port to 5000 if not defined in ..env file


// secret variables located in ..env file
const mongodb_cluster = process.env.MONGODB_CLUSTER;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const PayPalEnvironment = process.env.PAYPAL_ENVIRONMENT;   // Import PayPal Environment from ..env file
const PayPalClientID = process.env.PAYPAL_CLIENT_ID;        // Import PayPal Client ID from ..env file
const PayPalSecret = process.env.PAYPAL_CLIENT_SECRET;      // Import PayPal Secret from ..env file
const PayPal_endpoint_url = PayPalEnvironment === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'; // Import PayPal endpoint URL from ..env file
const projectID = process.env.CAPTCHA_PROJECT_ID            // Import Captcha Project ID from ..env file
const recaptchaKey = process.env.CAPTCHA_SECRET_KEY         // Import Captcha Secret Key from ..env file
process.env.GOOGLE_APPLICATION_CREDENTIALS = './thevintagegarage-1715977793921-f27e14d35c3e.json';

// importing the database object from databaseConnection.js file
var { database } = include('databaseConnection');

// referencing to admins and users collection in database
const adminCollection = database.db(mongodb_database).collection('admins');
const userCollection = database.db(mongodb_database).collection('users');

const categoryCollection = database.db(mongodb_database).collection('categories');
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
// Format amounts with commas
function formatAmount(amount) {
    return amount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// Make the helper function available in EJS templates
app.use((req, res, next) => {
    res.locals.formatAmount = formatAmount; // Make formatAmount available in templates
    next();
});

// creating a session
app.use(session({
    secret: node_session_secret,
    saveUninitialized: true,
    resave: true,
    store: mongoStore,
    cookie: { maxAge: 60 * 60 * 1000 * 10 }
}));

app.use((req, res, next) => {
    req.session = req.session || {};

    if (!req.session.cart) {
        req.session.cart = [];
    }
    res.locals.cartItemCount = req.session.cart ? req.session.cart.length : 0;
    res.locals.subCategories = [];
    next();
});

app.use('/filter', searchRoute);
app.use('/admin', adminRoute);
app.use('/cart', cartRoute);

app.get('/', async (req, res) => {

    // Set Up variables
    const isLoggedIn = req.session.loggedIn;
    const isAdmin = req.session.isAdmin || false;
    let searchKey = (req.session.keyword == null) ? "" : req.session.keyword;
    let maximumPrice = (req.session.maxPrice > 0) ? req.session.maxPrice : 100000000;
    let categoryTab = (req.session.category == null) ? "" : `> ${req.session.category}`;
    let subCategoryTab = (req.session.subcategory == null) ? "" : `> ${req.session.subcategory}`;
    let orderCode = (req.session.sortBy === "descending") ? -1 : 1;
    let categoryKeyword = (req.session.category == null) ? "" : req.session.category;
    let subCategoryKeyword = (req.session.subcategory == null) ? "" : req.session.subcategory;
    let filtersHeader = [`Category ${categoryTab} ${subCategoryTab}`, "Sorting", "Price"];
    let filterAnchors = ["Category", "Sorting", "Price"];
    let prices = [];


    try {
        // Get current listing collection
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const featureVideoCollection = database.db(mongodb_database).collection('featureVideo');

        // Fetch all prices
        prices = await fetchAllPrices();
        console.log(prices); // debugging

        // Fetch featured items
        const featuredItems = await productsCollection.find({ isFeatureItem: true }).toArray();


        // Called here to dynamically get the price through the category type
        let currentListings = await productsCollection.find({
            isFeatureItem: false,
            item_title: { $regex: searchKey, $options: 'i' },
            item_category: { $regex: categoryKeyword },
            item_sub_category: { $regex: subCategoryKeyword }
        }).sort({ item_price: orderCode });

        // turn into array and push price field into the prices array
        let currentListingsArray = await currentListings.toArray();
        currentListingsArray.forEach(function (item) {
            prices.push(item.item_price)
        });

        // close resources
        currentListings.close();

        // sort prices to make it easy on finding min and max
        const sortedPrices = prices.sort(function (a, b) {
            if (a < b)
                return 1;
            else if (a > b)
                return -1;
            else
                return 0;
        });

        // pagination set up
        let pageIndexes = [];
        let previousIndex = req.session.pageIndex - 1;
        let nextIndex = previousIndex + 2;
        let numberOfPages = sortedPrices.length / 18;
        if (previousIndex < 1)
            previousIndex = 1;

        if (nextIndex >= numberOfPages)
            nextIndex--;

        for (let i = 0; i <= (numberOfPages); i++)
            pageIndexes.push(i + 1);

        const skips = 18 * (((req.session.pageIndex - 1) < 0) ? 0 : (req.session.pageIndex - 1));

        // call another find to finally get the current 18 items in a page
        currentListingsArray = await productsCollection.find({
            isFeatureItem: false,
            item_title: { $regex: searchKey, $options: 'i' },
            item_price: { $lt: Math.round(maximumPrice) },
            item_category: { $regex: categoryKeyword },
            item_sub_category: { $regex: subCategoryKeyword }
        }).sort({ item_price: orderCode }).skip(skips)
            .limit(18)
            .toArray();

        // initially set to 0
        req.session.pageIndex = 0;

        const subCategories = await categoryCollection.find({ category_type: req.session.category }).project({ _id: 0, sub_categories: 1 }).toArray();
        let bodyFilters;
        if (subCategories.length < 1 || subCategories[0].sub_categories.length < 1)
            bodyFilters = getBodyFilters(sortedPrices[0], sortedPrices[prices.length - 1], maximumPrice, []);
        else
            bodyFilters = getBodyFilters(sortedPrices[0], sortedPrices[prices.length - 1], maximumPrice, subCategories[0].sub_categories);


        const featureVideo = await featureVideoCollection.findOne({});

        res.render("landing", {
            isLoggedIn,
            currentListings: currentListingsArray,
            filterHeaders: filtersHeader,
            filtersAnchor: filterAnchors,
            filterStuff: bodyFilters,
            categories: await getCategoriesNav(),
            isAdmin: isAdmin,
            paginationIndex: pageIndexes,
            previousPage: previousIndex,
            nextPage: nextIndex,
            featureVideo: featureVideo,
            featuredItems: featuredItems
        });
    } catch (error) {
        console.error('Failed to fetch current listings:', error);
        res.render("landing", { isLoggedIn: isLoggedIn, categories: [], isAdmin: isAdmin, currentListings: [], featureVideo: null });
    }
});

app.post('/page=:index', async (req, res) => {
    req.session.pageIndex = req.params.index;
    res.redirect('/');
})

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

async function fetchAllPrices() {
    try {
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const prices = await productsCollection.find({}, { projection: { item_price: 1 } }).toArray();
        return prices.map(item => item.item_price);
    } catch (error) {
        console.error('Failed to fetch prices:', error);
        return [];
    }
}


app.get("/loginPortal", (req, res) => {
    res.render('loginPortal');
})


app.get('/userLogIn', (req, res) => {
    res.render("userLogIn");
});

app.get('/userNewLogIn', (req, res) => {
    res.render("userNewLogIn");
});

app.post('/userLogInSubmit', async (req, res) => {

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
        res.render('product-info', { item: item, isLoggedIn: isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
    } catch (error) {
        console.error('Failed to fetch item:', error);
        res.status(500).send('Error fetching item details');
    }
});


app.get('/about', async (req, res) => {
    const isLoggedIn = req.session.loggedIn;
    res.render("about", { isLoggedIn: isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
});

app.get('/contact-us', async (req, res) => {
    const isLoggedIn = req.session.loggedIn;
    res.render("contact", { isLoggedIn: isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
});

app.get('/manageUser', async (req, res) => {
    if (req.session.loggedIn) {
        const isLoggedIn = req.session.loggedIn;
        res.render("user-management", { isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });

    }
    else {
        res.redirect('/userLogIn');
    }
});

app.get('/pastOrders', async (req, res) => {
    try {
        const ordersCollection = database.db(MONGODB_DATABASE).collection('orders');
        const userOrders = await ordersCollection.find({ userId: req.session.userId }).toArray();
        const isLoggedIn = req.session.loggedIn;
        res.render('pastOrders', {
            orders: userOrders,
            isLoggedIn,
            isAdmin: req.session.isAdmin,
            categories: await getCategoriesNav()
        });
    } catch (error) {
        console.error('Error fetching past orders:', error);
        res.status(500).send('Error fetching past orders');
    }
});

// TODO: Can this be removed?
async function addTestOrder() {
    try {
        const ordersCollection = database.db(mongodb_database).collection('orders');
        const testOrder = {
            userId: 'testUserId',
            date: new Date(),
            totalAmount: 100.00,
            items: [
                {
                    item_title: 'Test Item 1',
                    item_price: 50.00,
                    item_quantity: 1
                },
                {
                    item_title: 'Test Item 2',
                    item_price: 25.00,
                    item_quantity: 2
                }
            ]
        };
        await ordersCollection.insertOne(testOrder);
        console.log('Test order added successfully');
    } catch (error) {
        console.error('Error adding test order:', error);
    }
}

addTestOrder();


app.get('/settings', async (req, res) => {
    if (req.session.loggedIn) {
        const isLoggedIn = req.session.loggedIn;
        const user = req.session.name;
        const email = req.session.email;
        res.render("settings", { isLoggedIn: isLoggedIn, isAdmin: req.session.isAdmin, user: user, email: email, categories: await getCategoriesNav() });
    }
    else {
        res.redirect('/adminLogIn');
    }
});

app.post('/changePassword', async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;
    const email = req.session.email;
    const isLoggedIn = req.session.loggedIn;
    const schema = Joi.object({
        currentPassword: Joi.string().required(),
        newPassword: Joi.string().min(3).required(),
        confirmPassword: Joi.any().valid(Joi.ref('newPassword')).required()
    });

    const validationResult = schema.validate({ currentPassword, newPassword, confirmPassword });
    if (validationResult.error) {
        console.log(validationResult.error);
        return res.render('settings', { isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav(), user: req.session.name, email, error: validationResult.error.message });
    }

    const user = await adminCollection.findOne({ email });
    if (!user) {
        console.log('User not found');
        return res.render('settings', { isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav(), user: req.session.name, email, error: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatch) {
        console.log('Wrong current password');
        return res.render('settings', { isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav(), user: req.session.name, email, error: 'Incorrect current password' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await adminCollection.updateOne({ email }, { $set: { password: hashedNewPassword } });
    req.session.password = hashedNewPassword;

    res.render('passwordUpdated', { isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
});

// Route to render feature video management page
app.get('/featureVideo', async (req, res) => {
    const featureVideoCollection = database.db(mongodb_database).collection('featureVideo');
    const featureVideo = await featureVideoCollection.findOne({});
    res.render('featureVideo', { featureVideo: featureVideo });
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

// ----------------- PayPal Payment START -----------------

async function getAccessToken() {
    const fetch = await import('node-fetch').then(module => module.default);
    const auth = `${PayPalClientID}:${PayPalSecret}`;
    const data = 'grant_type=client_credentials';

    const response = await fetch(`${PayPal_endpoint_url}/v1/oauth2/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + Buffer.from(auth).toString('base64')
        },
        body: data
    });
    const json = await response.json();
    return json.access_token;
}

app.post('/create-paypal-order', async (req, res) => {
    try {
        const fetch = await import('node-fetch').then(module => module.default);
        const accessToken = await getAccessToken();

        const { intent, purchase_units, insuranceTotal, shippingTotal, taxTotal, finalTotal } = req.body;

        const orderData = {
            intent: intent.toUpperCase(),
            purchase_units: [{
                amount: {
                    currency_code: "CAD",
                    value: finalTotal.toFixed(2),
                    breakdown: {
                        item_total: { value: (finalTotal - insuranceTotal - shippingTotal - taxTotal).toFixed(2), currency_code: "CAD" },
                        shipping: { value: shippingTotal.toFixed(2), currency_code: "CAD" },
                        insurance: { value: insuranceTotal.toFixed(2), currency_code: "CAD" },
                        tax_total: { value: taxTotal.toFixed(2), currency_code: "CAD" }
                    }
                }
            }]
        };

        const response = await fetch(`${PayPal_endpoint_url}/v2/checkout/orders`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`
            },
            body: JSON.stringify(orderData)
        });

        const json = await response.json();
        res.send(json);
    } catch (err) {
        console.error('Error creating PayPal order:', err);
        res.status(500).send(err);
    }
});

app.post('/mark-items-sold', async (req, res) => {
    const itemIds = req.query.itemIds ? req.query.itemIds.split(',') : [];

    try {
        if (itemIds.length > 0) {
            const productsCollection = database.db(mongodb_database).collection('listing_items');
            await productsCollection.updateMany(
                { _id: { $in: itemIds.map(id => new ObjectId(id)) } },
                { $set: { isSold: true } }
            );
        }

        // Clear the cart
        req.session.cart = [];
        req.session.save(err => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).send('Error clearing the cart');
            }
            res.render('paypalSuccess', { message: 'Payment successful, items marked as sold.' });
        });
    } catch (error) {
        console.error('Error updating items as sold:', error);
        res.status(500).send('Error updating items as sold: ' + error.message);
    }
});


// ----------------- PayPal Payment END -----------------

// ----------------- Stripe Payment START -----------------

const stripe = require('stripe')('sk_test_51OZSVHAcq23T9yD7gpE3kQS73T5AnO6UEaecXMwkzvGc9hVh1QlPNFmM3rzI9cxJ2tU2FtUAPzvcSc1obqPcrUfZ00PojCiOni');

app.post('/create-checkout-session', async (req, res) => {
    try {
        // Extract product IDs from the POST data
        const itemIds = req.body.productIds;
        const insuranceTotal = parseFloat(req.body.insuranceTotal) || 0;
        const shippingTotal = parseFloat(req.body.shippingTotal) || 0;
        const taxTotal = parseFloat(req.body.taxTotal) || 0;

        const YOUR_DOMAIN = 'http://localhost:5000'; // Replace with clients domain

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
            quantity: 1,
        }));

        // Include shipping, insurance, and tax as separate line items
        if (shippingTotal > 0) {
            line_items.push({
                price_data: {
                    currency: 'cad',
                    product_data: {
                        name: 'Shipping'
                    },
                    unit_amount: Math.round(shippingTotal * 100), // Convert price to cents
                },
                quantity: 1,
            });
        }

        if (insuranceTotal > 0) {
            line_items.push({
                price_data: {
                    currency: 'cad',
                    product_data: {
                        name: 'Insurance'
                    },
                    unit_amount: Math.round(insuranceTotal * 100), // Convert price to cents
                },
                quantity: 1,
            });
        }

        if (taxTotal > 0) {
            line_items.push({
                price_data: {
                    currency: 'cad',
                    product_data: {
                        name: 'Tax'
                    },
                    unit_amount: Math.round(taxTotal * 100), // Convert price to cents
                },
                quantity: 1,
            });
        }

        // Create Stripe checkout session
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items,
            mode: 'payment',
            success_url: `${YOUR_DOMAIN}/StripeSuccess?itemIds=${itemIds.join(',')}`,
            cancel_url: `${YOUR_DOMAIN}/StripeCancel`,
        });

        // Redirect the client to the Stripe checkout
        res.redirect(303, session.url);
    } catch (error) {
        console.error('Failed to create checkout session:', error);
        res.status(500).send('Error creating checkout session: ' + error.message);
    }
});

app.get('/StripeSuccess', async (req, res) => {
    const itemIds = req.query.itemIds ? req.query.itemIds.split(',') : [];

    try {
        if (itemIds.length > 0) {
            const productsCollection = database.db(mongodb_database).collection('listing_items');
            await productsCollection.updateMany(
                { _id: { $in: itemIds.map(id => new ObjectId(id)) } },
                { $set: { isSold: true } }
            );
        }

        // Clear the cart
        req.session.cart = [];
        req.session.save(err => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).send('Error clearing the cart');
            }
            res.render('StripeSuccess', { message: 'Payment successful, items marked as sold.' });
        });
    } catch (error) {
        console.error('Error updating items as sold:', error);
        res.status(500).send('Error updating items as sold: ' + error.message);
    }
});


app.get('/StripeCancel', (req, res) => {
    res.render('StripeCancel');
});

// ----------------- Stripe Payment END -----------------

// ----------------- Email Sending START -----------------
const mailgun = new Mailgun(formData);
const mg = mailgun.client({ 
    username: 'api', 
    key: process.env.MAILGUN_API_KEY 
});

const sendContactUsEmail = (contactDetails) => {
    const messageData = {
        from: 'thevintagegaragetest@gmail.com',
        to: 'ajgabl18@gmail.com',
        subject: 'New Contact Us Message',
        text: `You have received a new message from ${contactDetails.name} (${contactDetails.email}):\n\n${contactDetails.message}`
    };

    return mg.messages.create(process.env.MAILGUN_DOMAIN, messageData);
};

const sendReferralEmail = (referralDetails) => {
    const messageData = {
        from: 'thevintagegaragetest@gmail.com',
        to: 'ajgabl18@gmail.com',
        subject: 'New Referral Message',
        text: `You have received a new referral from ${referralDetails.orgName} (${referralDetails.email}):\n\n${referralDetails.message}`
    };

    return mg.messages.create(process.env.MAILGUN_DOMAIN, messageData);
};

app.post('/sendContactUsEmail', (req, res) => {
    const contactDetails = req.body;

    sendContactUsEmail(contactDetails)
        .then(info => {
            console.log('Email sent:', info);
            res.json({ success: true });
        })
        .catch(error => {
            console.error('Error sending email:', error);
            res.json({ success: false, message: error.message });
        });
});

app.post('/sendReferralEmail', (req, res) => {
    const referralDetails = req.body;

    sendReferralEmail(referralDetails)
        .then(info => {
            console.log('Referral email sent:', info);
            res.json({ success: true });
        })
        .catch(error => {
            console.error('Error sending referral email:', error);
            res.json({ success: false, message: error.message });
        });
});

// ----------------- Email Sending END -----------------

// ----------------- reCAPTCHA START -----------------

async function createAssessment({ token, recaptchaAction }) {
    const client = new RecaptchaEnterpriseServiceClient();
    const projectPath = client.projectPath(projectID);

    const request = {
        assessment: {
            event: {
                token: token,
                siteKey: recaptchaKey,
            },
        },
        parent: projectPath,
    };

    const [response] = await client.createAssessment(request);

    if (!response.tokenProperties.valid) {
        console.log(`The CreateAssessment call failed because the token was: ${response.tokenProperties.invalidReason}`);
        return null;
    }

    if (response.tokenProperties.action === recaptchaAction) {
        console.log(`The reCAPTCHA score is: ${response.riskAnalysis.score}`);
        response.riskAnalysis.reasons.forEach((reason) => {
            console.log(reason);
        });
        return response.riskAnalysis.score;
    } else {
        console.log("The action attribute in your reCAPTCHA tag does not match the action you are expecting to score");
        return null;
    }
}

app.post('/submitContactForm', async (req, res) => {
    const { name, email, message, token } = req.body;

    console.log('Received form data:', { name, email, message, token });

    const score = await createAssessment({ token, recaptchaAction: 'submit' });

    if (score === null || score < 0.5) {
        return res.status(400).send('Failed reCAPTCHA verification');
    }

    console.log('Form submitted successfully');
    res.send('Form submitted successfully');
});

// ----------------- reCAPTCHA END -----------------