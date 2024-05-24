
/**
 * Basic Require Configs.
 */
require('dotenv').config();                                    // Import dotenv module to read ..env file
require('./utils');                                            // Import utils.js file to define include function

/*
 * Assign most variables
 *
 */
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
const {RecaptchaEnterpriseServiceClient} = require('@google-cloud/recaptcha-enterprise'); // Import recaptcha-enterprise module to interact with Google Recaptcha Enterprise API
const bodyParser = require('body-parser');                      // Import body-parser module to parse request body
const { sendContactUsEmail, sendReferralEmail, sendOrderConfirmationEmail, sendOrderNotificationEmail } = require('./routes/mailer'); // Import mailer.js file to send emails
const moment = require('moment-timezone');

// Get most of the functions.
const { getBodyFilters, getCategoriesNav } = require('./controller/htmlContent');
const { sendContactUsEmail, sendReferralEmail, sendOrderConfirmationEmail, sendOrderNotificationEmail } = require('./routes/mailer'); // Import mailer.js file to send emails
// Import Variables
const {adminCollection, categoryCollection} = require('./database/constants');

// Start express application
const app = express();

app.set('view engine', 'ejs');                              // Set view engine to ejs

app.use(express.urlencoded({ extended: true }));            // parse urlencoded request bodies
app.use(express.static('public'));                          // serve static image files
app.use(express.static('css'));                             // serve static css files
app.use(express.static('js'));                              // serve static js files
app.use(express.json());                                    // parse json request bodies

// Allow body fields to be printed as JSON.
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Create routers for each duplicate or related routes.
const filterRouter = require('./routes/filter');
const adminRouter = require('./routes/admin');
const cartRouter = require('./routes/cart');
const userRouter = require('./routes/user');

const port = process.env.PORT || 5000;                      // Set port to 5000 if not defined in ..env file


// secret variables located in ..env file
// Mongo Database Variables
const mongodb_cluster = process.env.MONGODB_CLUSTER;                    // MONGODB App
const mongodb_user = process.env.MONGODB_USER;                          // MONGODB Owner's Username
const mongodb_password = process.env.MONGODB_PASSWORD;                  // MONGODB Owner's Password
const mongodb_database = process.env.MONGODB_DATABASE;                  // MONGODB Database
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;      // MONGODB Session

const node_session_secret = process.env.NODE_SESSION_SECRET;            // Node secret setup
const PayPalEnvironment = process.env.PAYPAL_ENVIRONMENT;               // Import PayPal Environment from ..env file
const PayPalClientID = process.env.PAYPAL_CLIENT_ID;                    // Import PayPal Client ID from ..env file
const PayPalSecret = process.env.PAYPAL_CLIENT_SECRET;                  // Import PayPal Secret from ..env file
const PayPal_endpoint_url = PayPalEnvironment === 'sandbox' ? 'https://api-m.sandbox.paypal.com' : 'https://api-m.paypal.com'; // Import PayPal endpoint URL from ..env file
const projectID = process.env.CAPTCHA_PROJECT_ID                 // Import Captcha Project ID from ..env file
const recaptchaKey = process.env.CAPTCHA_SECRET_KEY              // Import Captcha Secret Key from ..env file
process.env.GOOGLE_APPLICATION_CREDENTIALS = './thevintagegarage-1715977793921-f27e14d35c3e.json';

// importing the database object from databaseConnection.js file
let { database } = include('databaseConnection');


// linking to mongoDb database
let mongoStore = MongoDBStore.create({
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

// Assign or setup variables before execution
app.use((req, res, next) => {
    req.session = req.session || {};

    if (!req.session.cart) {
        req.session.cart = [];
    }
    res.locals.cartItemCount = req.session.cart ? req.session.cart.length : 0;
    res.locals.subCategories = [];
    next();
});

// Assign the filter route to its router
app.use('/filter', filterRouter);

// Assign the admin route to its router
app.use('/admin', adminRouter);

// Assign the cart route to its router
app.use('/cart', cartRouter);

// Assign the user route to its router
app.use('/user', userRouter)

// Landing Page Route
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
        prices = await fetchAllPrices(searchKey, categoryKeyword, subCategoryKeyword);

        // Fetch featured items
        const featuredItems = await productsCollection.find({ isFeatureItem: true }).toArray();


        // Called here to dynamically get the price through the category type
        let currentListings;

        // sort prices to make it easy on finding min and max
        const sortedPrices = prices.sort(function (a, b) {
            if (a < b)
                return 1;
            else if (a > b)
                return -1;
            else
                return 0;
        });

        // Pagination set up
        let pageIndexes = [];
        let previousIndex = req.session.pageIndex - 1;
        let nextIndex = previousIndex + 2;
        if (previousIndex < 1)
            previousIndex = 1;
        // TODO: TO MODIFY AMOUNT OF PAGES PER PAGE, CHANGE THE NUMBER.
        let numberOfPages = sortedPrices.length / /* TODO: Change this number to modify */ 18;

        if (nextIndex >= numberOfPages)
            nextIndex--;

        // Assign the number indexes to display
        for (let i = 0; i <= (numberOfPages); i++)
            pageIndexes.push(i + 1);

        // TODO: TO MODIFY AMOUNT OF PAGES PER PAGE, CHANGE THE FIRST NUMBER.
        const skips = /* TODO: Change this number to modify */ 18 * (((req.session.pageIndex - 1) < 0) ? 0 : (req.session.pageIndex - 1));

        /*
        Call its designed filters.
        Skip is based on the current page.
        Limit is how many items (maximum) should display per page.
         */
        currentListings = await productsCollection.find({
            isFeatureItem: false,
            item_title: { $regex: searchKey, $options: 'i' },
            item_price: { $lt: Math.round(maximumPrice) },
            item_category: { $regex: categoryKeyword },
            item_sub_category: { $regex: subCategoryKeyword }
        }).sort({ item_price: orderCode }).skip(skips)
            .limit(18)
            .toArray();

        // initially page index to 0 to prevent miscalculations.
        req.session.pageIndex = 0;

        // Obtain Sub-Categories.
        const subCategories = await categoryCollection.find({ category_type: req.session.category }).project({ _id: 0, sub_categories: 1 }).toArray();
        let bodyFilters;

        if (subCategories.length < 1 || subCategories[0].sub_categories.length < 1)
            bodyFilters = getBodyFilters(sortedPrices[0], sortedPrices[prices.length - 1], maximumPrice, []);
        else
            bodyFilters = getBodyFilters(sortedPrices[0], sortedPrices[prices.length - 1], maximumPrice, subCategories[0].sub_categories);

        // Find one featured video for the bottom of the page.
        const featureVideo = await featureVideoCollection.findOne({});

        // Render landing page.
        res.render("landing", {
            isLoggedIn,
            currentListings: currentListings,
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
        res.render("landing", {
            isLoggedIn: isLoggedIn,
            currentListings: [],
            filterHeaders: [],
            filterAnchors: [],
            filterStuff: "",
            categories: [],
            isAdmin: isAdmin,
            paginationIndex: 0,
            previousPage: 0,
            nextPage: 0,
            featuredItems: null,
            featureVideo: null
        });
    }
});

// With each page, get its index and assign the page index to that.
app.post('/page=:index', async (req, res) => {
    req.session.pageIndex = req.params.index;
    res.redirect('/');
})

/**
 * Hashes all the passwords to ensure security.
 */
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

/**
 * Fetches all the prices in the database based on the filters used.
 * @param searchKey a string, a pattern used to check the listings that contain that pattern.
 * @param categoryKeyword a string, a category type to check the listings that has that category.
 * @param subCategoryKeyword a string, a sub-category type to check the listings that has that sub-category.
 * @returns all the non-featured items' prices based on the search, category, sub-category filter.
 */
async function fetchAllPrices(searchKey, categoryKeyword, subCategoryKeyword) {
    try {
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const prices = await productsCollection.find(
            {
                isFeatureItem: false,
                item_title: { $regex: searchKey, $options: 'i' },
                item_category: { $regex: categoryKeyword },
                item_sub_category: { $regex: subCategoryKeyword }
            },
            { projection: { item_price: 1 } }).toArray();
        return prices.map(item => item.item_price);
    } catch (error) {
        console.error('Failed to fetch prices:', error);
        return [];
    }
}

// Route for login portal
app.get("/loginPortal", (req, res) => {
    res.render('loginPortal');
})

// Route for sign-out
app.get('/signout', (req, res) => {
    req.session.destroy()
    res.redirect('/');
});

// Route for each product based on the ID
app.get('/product-info/:id', async (req, res) => {
    try {
        // get the id parameters
        const itemId = req.params.id;
        const productsCollection = database.db(mongodb_database).collection('listing_items');

        const item = await productsCollection.findOne({ _id: new ObjectId(itemId) });

        if (!item) {
            res.status(404).send('Item not found');
            return;
        }

        res.render('product-info', { item: item, isLoggedIn: req.session.loggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
    } catch (error) {
        console.error('Failed to fetch item:', error);
        res.status(500).send('Error fetching item details');
    }
});

// Route for about page
app.get('/about', async (req, res) => {
    res.render("about", { isLoggedIn: req.session.loggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
});

// Route for contact us page
app.get('/contact-us', async (req, res) => {
    res.render("contact", { isLoggedIn: req.session.loggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
});

// Route for managing a user
app.get('/manageUser', async (req, res) => {
    if (req.session.loggedIn) {
        const isLoggedIn = req.session.loggedIn;
        res.render("user-management", { isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav() });
    }
    else {
        res.redirect('/user/LogIn');
    }
});

// Route for past orders.
app.get('/pastOrders', async (req, res) => {
    try {
        const ordersCollection = database.db(mongodb_database).collection('orders');
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

// Route for settings.
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

// Route for changing password
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

/**
 *  Based on performing the Paypal authentication to achieve access token.
 * @returns Get the JSON access token
 */
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

// Route post method for creation of paypal order.
app.post('/create-paypal-order', async (req, res) => {
    try {
        const fetch = await import('node-fetch').then(module => module.default);
        const accessToken = await getAccessToken();

        const { intent, insuranceTotal, shippingTotal, taxTotal, finalTotal, subtotal, email, address, city, state, zip, itemIds } = req.body;

        const orderData = {
            intent: intent.toUpperCase(),
            purchase_units: [{
                amount: {
                    currency_code: "CAD",
                    value: finalTotal.toFixed(2),
                    breakdown: {
                        item_total: { value: (subtotal || 0).toFixed(2), currency_code: "CAD" },
                        shipping: { value: (shippingTotal || 0).toFixed(2), currency_code: "CAD" },
                        insurance: { value: (insuranceTotal || 0).toFixed(2), currency_code: "CAD" },
                        tax_total: { value: (taxTotal || 0).toFixed(2), currency_code: "CAD" }
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

// Post method for sold items.
app.post('/mark-items-sold', async (req, res) => {
    const { itemIds, email, address, city, state, zip, shippingTotal, insuranceTotal, taxTotal, finalTotal, shippingPickup } = req.body;

    try {
        if (itemIds && Array.isArray(itemIds) && itemIds.length > 0) {
            const productsCollection = database.db(mongodb_database).collection('listing_items');
            const items = await productsCollection.find({ _id: { $in: itemIds.map(id => new ObjectId(id)) } }).toArray();

            // To get the current date and time in PST
            const soldDate = moment().tz('America/Los_Angeles').toDate();
            
            await productsCollection.updateMany(
                { _id: { $in: itemIds.map(id => new ObjectId(id)) } },
                { $set: { isSold: true, soldDate: soldDate, soldTo: email } }
            );

            const itemDetails = items.map(item => `${item.item_title} - $${item.item_price} - ${shippingPickup[index]}`).join('\n');
            const ownerEmail = "ajgabl18@gmail.com";

            const orderDetails = `
            Date of purchase: ${soldDate} \n\n   
            Items: ${itemDetails}
            Shipping: $${shippingTotal.toFixed(2)}
            Insurance: $${insuranceTotal.toFixed(2)}
            Taxes: $${taxTotal.toFixed(2)}
            Total: $${finalTotal.toFixed(2)}
            `;

            const customerDetails = `
                Buyer Email: ${email}
                Shipping Address: ${address}, ${city}, ${state}, ${zip}
            `;

            sendOrderConfirmationEmail(email, orderDetails);
            sendOrderNotificationEmail(ownerEmail, orderDetails, customerDetails);
        }

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

// Post method for creation of a checkout session
app.post('/create-checkout-session', async (req, res) => {
    try {
        let { productIds, insuranceTotal, shippingTotal, taxTotal, finalTotal, subtotal, email, address, city, state, zip } = req.body;

        const YOUR_DOMAIN = 'http://localhost:5000'; // Replace with client's domain when finalized

        if (!productIds) {
            throw new Error('Product IDs not received');
        }

        if (!Array.isArray(productIds)) {
            productIds = [productIds];
        }

        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const items = await productsCollection.find({
            '_id': { $in: productIds.map(id => ObjectId.createFromHexString(id)) }
        }).toArray();

        const line_items = items.map(item => ({
            price_data: {
                currency: 'cad',
                product_data: {
                    name: item.item_title,
                    images: [item.product_img_URL[0]]
                },
                unit_amount: Math.round(item.item_price * 100), 
            },
            quantity: 1,
        }));

        if (shippingTotal > 0) {
            line_items.push({
                price_data: {
                    currency: 'cad',
                    product_data: {
                        name: 'Shipping'
                    },
                    unit_amount: Math.round(shippingTotal * 100), 
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
                    unit_amount: Math.round(insuranceTotal * 100), 
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
                    unit_amount: Math.round(taxTotal * 100), 
                },
                quantity: 1,
            });
        }

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items,
            mode: 'payment',
            success_url: `${YOUR_DOMAIN}/StripeSuccess?itemIds=${productIds.join(',')}&email=${email}&address=${address}&city=${city}&state=${state}&zip=${zip}&subtotal=${subtotal}&shippingTotal=${shippingTotal}&insuranceTotal=${insuranceTotal}&taxTotal=${taxTotal}&finalTotal=${finalTotal}`,
            cancel_url: `${YOUR_DOMAIN}/StripeCancel`,
            customer_email: email 
        });

        res.redirect(303, session.url);
    } catch (error) {
        console.error('Failed to create checkout session:', error);
        res.status(500).send('Error creating checkout session: ' + error.message);
    }
});

// Route for successful process with stripe
app.get('/StripeSuccess', async (req, res) => {
    const itemIds = req.query.itemIds ? req.query.itemIds.split(',') : [];
    const email = req.query.email;
    const address = req.query.address || '';
    const city = req.query.city || '';
    const state = req.query.state || '';
    const zip = req.query.zip || '';
    const shippingTotal = parseFloat(req.query.shippingTotal);
    const insuranceTotal = parseFloat(req.query.insuranceTotal);
    const taxTotal = parseFloat(req.query.taxTotal);
    const finalTotal = parseFloat(req.query.finalTotal);
    const shippingPickup = req.query.shippingPickup ? req.query.shippingPickup.split(',') : [];

    // Debugging log
    console.log('Received itemIds:', itemIds);
    console.log('Received shippingPickup values:', shippingPickup);

    try {
        if (itemIds.length > 0) {
            const productsCollection = database.db(mongodb_database).collection('listing_items');
            const items = await productsCollection.find({ _id: { $in: itemIds.map(id => new ObjectId(id)) } }).toArray();

            // To get the current date and time in PST
            const soldDate = moment().tz('America/Los_Angeles').toDate();
            
            await productsCollection.updateMany(
                { _id: { $in: itemIds.map(id => new ObjectId(id)) } },
                { $set: { isSold: true, soldDate: soldDate, soldTo: email } }
            );

            const itemDetails = items.map((item, index) => `${item.item_title} - $${item.item_price} - ${shippingPickup[index] || 'Pickup'}`).join('\n');
            const ownerEmail = "ajgabl18@gmail.com";

            const orderDetails = `
                Date of purchase: ${soldDate.toLocaleString('en-US', { timeZone: 'America/Los_Angeles' })} \n\n   
                Items: \n${itemDetails}
                Shipping: $${shippingTotal.toFixed(2)}
                Insurance: $${insuranceTotal.toFixed(2)}
                Taxes: $${taxTotal.toFixed(2)}
                Total: $${finalTotal.toFixed(2)}
            `;

            const customerDetails = `
                Buyer Email: ${email}
                Shipping Address: ${address}, ${city}, ${state}, ${zip}
            `;

            sendOrderConfirmationEmail(email, orderDetails);
            sendOrderNotificationEmail(ownerEmail, orderDetails, customerDetails);
        }

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

// Route for cancellation of the stripe process
app.get('/StripeCancel', (req, res) => {
    res.render('StripeCancel');
});

// ----------------- Stripe Payment END -----------------

// ----------------- Email Sending START -----------------

// Post method on sending contact us email
app.post('/sendContactUsEmail', async (req, res) => {
    const { name, email, message, token } = req.body;

    console.log('Received contact form data:', { name, email, message, token });

    const score = await createAssessment({ token, recaptchaAction: 'submit' });

    if (score === null || score < 0.5) {
        return res.status(400).json({ success: false, message: 'Failed reCAPTCHA verification' });
    }

    sendContactUsEmail({ name, email, message })
        .then(info => {
            console.log('Email sent:', info);
            res.json({ success: true });
        })
        .catch(error => {
            console.error('Error sending email:', error);
            res.json({ success: false, message: error.message });
        });
});

// Post method for sending referral email.
app.post('/sendReferralEmail', async (req, res) => {
    const { organisation, email, message, token } = req.body;

    console.log('Received referral form data:', { organisation, email, message, token });

    const score = await createAssessment({ token, recaptchaAction: 'submit' });

    if (score === null || score < 0.5) {
        return res.status(400).json({ success: false, message: 'Failed reCAPTCHA verification' });
    }

    sendReferralEmail({ organisation, email, message })
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