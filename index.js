require ('dotenv').config();                                // Import dotenv module to read ..env file
require ('./utils');                                        // Import utils.js file to define include function
const express = require('express');                         // Import express module to create server
const session = require('express-session');                 // Import express-session module to manage session
const MongoDBStore = require('connect-mongo');              // Import connect-mongo module to store session in MongoDB
const Joi = require('joi');                                 // include the joi module
const bcrypt = require('bcrypt');                           // include the bcrypt module
const { ObjectId } = require('mongodb');                    // include the ObjectId module





const app = express();
app.set('view engine', 'ejs');                              // Set view engine to ejs

app.use(express.urlencoded({ extended: false }));           // parse urlencoded request bodies
app.use(express.static('public'));                          // serve static image files
app.use(express.static('css'));                             // serve static css files
app.use(express.static('js'));                              // serve static js files
app.use(express.json());                                    // parse json request bodies

const port = process.env.PORT || 5000;                      // Set port to 8000 if not defined in ..env file


////// **************************** Requires Further Development (this is for the "ADD NEW LISTING) MAY BE USEFUL****************************

// const multer = require('multer');
// const storage = multer.diskStorage({
//     destination: function (req, file, cb) {
//         cb(null, 'public/uploads/');
//     },
//     filename: function (req, file, cb) {
//         cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
//     }
// });
// const upload = multer({ storage: storage });


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

function getBodyFilters()
{
    // TODO / INFO: ******************************** This is the Sub-Category template ********************************
    /*<div className="col accordion">
        <h2 className="accordion-header" id="heading<%= header %>">
            <button className="accordion-button bg-white" type="button" data-bs-toggle="collapse"
                    data-bs-target="#<%= header %>" aria-expanded="true" aria-controls="<%= header %>">
                <strong>WA</strong> <!-- TODO: Variable -->
            </button>
        </h2>
        <div id="<%= header %>" className="accordion-collapse collapse show" aria-labelledby="heading<%= header %>"
             data-bs-parent="#accordionExample">
            <div className="accordion-body">
                <
                %- choice %>
            </div>
        </div>
    </div>*/

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
        "            <label for=\"priceRange\" class=\"form-label\">$0</label>\n" +
        "        </div>\n" +
        "        <div class=\"col text-middle\">\n" +
        "            <label id=\"userRange\" for=\"priceRange\" class=\"form-label\">$199.99</label>\n" +
        "        </div>\n" +
        "        <div class=\"col text-end\">\n" +
        "            <label for=\"priceRange\" class=\"form-label\">$199.99</label>\n" +
        "        </div>\n" +
        "        <input type=\"range\" class=\"form-range\" min=\"0\" max=\"199.99\" step=\"5\" id=\"priceRange\" oninput=\"document.getElementById('userRange').innerHTML = `$${this.value}`\">\n" +
        "    </div>"
    ];
}
app.get('/search/', async (req, res) => {
    try
    {
        // Place this as a public or constant variable.
        let filtersHeader = ["Categories", "Price"];
        let bodyFilters = getBodyFilters();

        res.render('catalog', {items: await fetchAllItems(),
            filterHeaders: filtersHeader,
            filterStuff: bodyFilters
        });
    }
    catch (error)
    {
        console.error("Failed to fetch items:", error);
        res.status(500).send('Error fetching items');
    }
})
app.get('/search/:key', async (req, res) => {
    try
    {
        let filtersHeader = ["Categories", "Price"];
        let bodyFilters = getBodyFilters();
        const searchKey = req.params.key;
        const productsColl = database.db(mongodb_database).collection('listing_items');
        const productList = await productsColl.find({item_title: {$regex: searchKey, $options: 'i'}}).toArray();
        res.render('catalog', {items: productList, keyword: req.params.key,
            filterHeaders: filtersHeader,
            filterStuff: bodyFilters});
    }
    catch (error)
    {
        console.error("Failed to fetch items:", error);
        res.status(500).send('Error fetching items');
    }
});

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

app.get('/addListing', (req, res) => {
    res.render('addListing');
});

////// **************************** Requires Further Development (this is for the "ADD NEW LISTING) MAY BE USEFUL****************************

// app.post('/submitListing', upload.fields([{name: 'product_img_URL'}, {name: 'product_video_URL'}]), async (req, res) => {
//     const { item_title, item_price, item_detailed_description, item_estimatedShippingCost, isFeatureItem, isAuctionItem, item_quantity, item_category } = req.body;
//     const product_img_URL = req.files['product_img_URL']?.map(file => file.path);
//     const product_video_URL = req.files['product_video_URL']?.map(file => file.path);

//     try {
//         await productsCollection.insertOne({
//             product_img_URL,
//             product_video_URL,
//             isFeatureItem: isFeatureItem === 'on',
//             isAuctionItem: isAuctionItem === 'on',
//             item_quantity: parseInt(item_quantity),
//             item_title,
//             item_price: parseFloat(item_price),
//             item_estimatedShippingCost: parseFloat(item_estimatedShippingCost),
//             item_detailed_description,
//             item_category: item_category.split(',').map(item => item.trim())
//         });
//         res.redirect('/manage');  // Redirect to manage page or confirmation page
//     } catch (error) {
//         console.error('Failed to insert new listing:', error);
//         res.status(500).send('Error submitting new listing');
//     }
// });


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