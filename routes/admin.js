const express = require('express');
const Joi = require("joi");
const bcrypt = require("bcrypt");
const {ObjectId} = require("mongodb");
const mailchimp = require("@mailchimp/mailchimp_marketing");
const router = express.Router();

const {MONGODB_DATABASE, PAYPAL_ENVIRONMENT, MAILCHIMP_API_KEY, MAILCHIMP_SERVER_PREFIX, MAILCHIMP_LIST_ID}= require('../.env');
const {adminCollection, userCollection, categoryCollection} = require('../database/constants')
const {database} = include('../databaseConnection');
const {getCategoriesNav} = require('../controller/htmlContent');
const {upload, deleteFromS3, featureVideoUpload, s3} = require("../controller/awsController");
const {DeleteObjectCommand} = require("@aws-sdk/client-s3");

// TODO: Done
router.get('/LogIn', (req, res) => {
    res.render("adminLogIn");
});

// TODO: Done
router.post('/LogInSubmit', async (req, res) => {

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
    req.session.isAdmin = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.password = user.password;
    req.session.userId = user._id;
    res.redirect("/");
});

// TODO: Done
router.get('/manage', async (req, res) => {
    if (req.session.loggedIn) {
        const isLoggedIn = req.session.loggedIn;
        res.render("product-management", {isLoggedIn,
            isAdmin: req.session.isAdmin,
            categories: await getCategoriesNav()
        });
    }
    else {
        res.redirect('/admin/LogIn');
    }
});

// TODO: Done
router.get('/manageUser', async (req, res) => {
    if (req.session.loggedIn) {
        const isLoggedIn = req.session.loggedIn;
        res.render("user-management", {isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav()});
    }
    else {
        res.redirect('/userLogIn');
    }
});

router.get('/pastOrders', async (req, res) => {
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

router.get('/addListing', async (req, res) => {

    res.render('addListing', {categories: await categoryCollection.find().toArray()});
});

// Route to handle form submission
router.post('/submitListing', upload.fields([{ name: 'photo', maxCount: 10 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    const photos = req.files['photo'] ? req.files['photo'].map(file => file.location) : [];
    const videos = req.files['video'] ? req.files['video'].map(file => file.location) : [];

    const listingItemsCollection = database.db(MONGODB_DATABASE).collection('listing_items');
    const document = {
        product_img_URL: photos,
        product_video_URL: videos,
        item_title: req.body.item_title,
        item_price: parseFloat(req.body.item_price) || 0.00,
        item_quantity: parseInt(req.body.item_quantity) || 0,
        item_detailed_description: req.body.item_detailed_description || '',
        item_estimatedShippingCost: parseFloat(req.body.item_estimatedShippingCost) || 0.0,
        item_estimatedInsuranceCost: parseFloat(req.body.item_estimatedInsuranceCost) || 0.0,
        isFeatureItem: req.body.isFeatureItem === 'true',
        item_category: Array.isArray(req.body.item_category) ? req.body.item_category.map(function(item)
        {
            return item.replace(/"/g, '');
        }) : [req.body.item_category.replace(/"/g, '')],
        item_sub_category: Array.isArray(req.body.item_sub_category) ? req.body.item_sub_category.map(function(item)
        {
            return item.replace(/"/g, '');
        }) : [req.body.item_sub_category.replace(/"/g, '')],
        status: 'available' // Default status when a listing is created
    };

    try {
        await listingItemsCollection.insertOne(document);
        res.redirect('/manage');
    } catch (error) {
        console.error('Error submitting new listing:', error);
        res.status(500).send('Failed to add new listing');
    }
});

router.get('/editListing/:id', async (req, res) => {
    const itemId = req.params.id;
    const isLoggedIn = req.session.loggedIn;
    console.log("Received ID for editing:", itemId);

    if (!ObjectId.isValid(itemId)) {
        return res.status(400).send('Invalid ID format');
    }

    try {
        const listing = await database.db(MONGODB_DATABASE).collection('listing_items').findOne({_id: new ObjectId(itemId)});
        if (!listing) {
            return res.status(404).send('Listing not found');
        }
        res.render('editListing', { listing, isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav()});
    } catch (error) {
        console.error('Failed to fetch listing:', error);
        res.status(500).send('Error fetching listing details');
    }
});

router.post('/updateListing/:id', upload.fields([{ name: 'photo', maxCount: 10 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
    const itemId = new ObjectId(req.params.id);
    console.log("Form submission data:", req.body);

    const photos = req.files['photo'] ? req.files['photo'].map(file => file.location) : [];
    const videos = req.files['video'] ? req.files['video'].map(file => file.location) : [];

    const removeImages = Array.isArray(req.body.remove_img_URL) ? req.body.remove_img_URL : [req.body.remove_img_URL].filter(Boolean);
    const removeVideos = Array.isArray(req.body.remove_video_URL) ? req.body.remove_video_URL : [req.body.remove_video_URL].filter(Boolean);

    try {
        const listing = await database.db(MONGODB_DATABASE).collection('listing_items').findOne({ _id: itemId });

        // Remove images from S3 and update listing
        if (removeImages.length > 0) {
            for (const url of removeImages) {
                await deleteFromS3(url);
            }
        }

        // Remove videos from S3 and update listing
        if (removeVideos.length > 0) {
            for (const url of removeVideos) {
                await deleteFromS3(url);
            }
        }

        const updatedImages = listing.product_img_URL.filter(url => !removeImages.includes(url)).concat(photos);
        const updatedVideos = listing.product_video_URL.filter(url => !removeVideos.includes(url)).concat(videos);

        const updateData = {
            item_title: req.body.item_title,
            item_price: parseFloat(req.body.item_price) || 0.00,
            item_quantity: parseInt(req.body.item_quantity) || 0,
            item_detailed_description: req.body.item_detailed_description || '',
            item_estimatedShippingCost: parseFloat(req.body.item_estimatedShippingCost) || 0.0,
            item_estimatedInsuranceCost: parseFloat(req.body.item_estimatedInsuranceCost) || 0.0,
            isFeatureItem: req.body.isFeatureItem ? req.body.isFeatureItem === 'true' : false,
            product_img_URL: updatedImages,
            product_video_URL: updatedVideos,
            status: req.body.status || 'available' // Allow status update
        };

        const result = await database.db(MONGODB_DATABASE).collection('listing_items').updateOne(
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

// Route to handle feature video upload
router.post('/submitFeatureVideo', featureVideoUpload.single('video'), async (req, res) => {
    if (!req.file) {
        return res.status(400).send('No video file uploaded.');
    }

    const videoURL = req.file.location;

    const featureVideoCollection = database.db(MONGODB_DATABASE).collection('featureVideo');
    await featureVideoCollection.updateOne({}, { $set: { url: videoURL } }, { upsert: true });

    res.redirect('/manage');
});

// Route to handle feature video removal
router.post('/removeFeatureVideo', async (req, res) => {
    const featureVideoCollection = database.db(MONGODB_DATABASE).collection('featureVideo');
    const featureVideo = await featureVideoCollection.findOne({});
    if (featureVideo && featureVideo.url) {
        const key = featureVideo.url.split('.com/')[1];
        const deleteParams = {
            Bucket: 'the-vintage-garage-test',
            Key: key
        };
        try {
            await s3.send(new DeleteObjectCommand(deleteParams));
            await featureVideoCollection.deleteOne({});
            res.redirect('/manage');
        } catch (error) {
            console.error('Error removing feature video:', error);
            res.status(500).send('Error removing feature video');
        }
    } else {
        res.redirect('/manage');
    }
});

router.get('/currentListings', async (req, res) => {
    try {
        const productsCollection = database.db(MONGODB_DATABASE).collection('listing_items');
        const currentListings = await productsCollection.find({ isFeatureItem: false }).toArray();
        res.render('currentListings', { listings: currentListings });
    } catch (error) {
        console.error('Failed to fetch current listings:', error);
        res.status(500).send('Error fetching current listings');
        // handling error case - passing empty array
        res.render('currentListings', { listings: [] }); // rendering the page even in case of error with an empty array
    }
});

router.get('/previousListings', async (req, res) => {
    try {
        const productsCollection = database.db(MONGODB_DATABASE).collection('listing_items');
        const soldListings = await productsCollection.find({ status: 'sold' }).toArray();
        const isLoggedIn = req.session.loggedIn;
        const isAdmin = req.session.isAdmin || false;

        res.render('previousListings', {
            listings: soldListings,
            isLoggedIn,
            isAdmin,
            categories: await getCategoriesNav()
        });
    } catch (error) {
        console.error('Failed to fetch previous listings:', error);
        res.status(500).send('Error fetching previous listings');
    }
});

router.get('/mailingList', async (req, res) => {
    try {
        mailchimp.setConfig({
            apiKey: MAILCHIMP_API_KEY,
            server: MAILCHIMP_SERVER_PREFIX
        });

        const response = await mailchimp.lists.getListMembersInfo(MAILCHIMP_LIST_ID);
        const subscribers = response.members.map(member => ({
            firstName: member.merge_fields.FNAME,
            lastName: member.merge_fields.LNAME,
            email: member.email_address
        }));

        res.render('mailingList', {
            people: subscribers
        });
    } catch (error) {
        console.error('Error fetching mailing list:', error);
        res.status(500).send('Error fetching mailing list');
    }
});

router.get('/adminUsers', async (req, res) => {
    try {
        const admins = await adminCollection.find().toArray();
        res.render('adminUsers', { users: admins });
    } catch (error) {
        console.error('Error fetching admin users:', error);
        res.status(500).send('Error fetching admin users');
    }
});

router.post('/addUser', async (req, res) => {
    const { name, email, password, userType } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        if (userType === 'admin') {
            await adminCollection.insertOne({ name, email, password: hashedPassword });
            req.session.loggedIn = true;
            res.redirect('/manage');
        } else if (userType === 'user') {
            await userCollection.insertOne({ name, email, password: hashedPassword });
            req.session.loggedIn = true;
            res.redirect('/manageUser');
        } else {
            res.status(400).send('Invalid user type');
        }
    } catch (error) {
        console.error('Error adding new user:', error);
        res.status(500).send('Failed to add new user');
    }
});

router.get('/editUser/:id', async (req, res) => {
    try {
        const user = await adminCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!user) {
            res.status(404).send('User not found');
            return;
        }
        const isLoggedIn = req.session.loggedIn;
        res.render('editUser', { user, isLoggedIn : isLoggedIn, isAdmin: req.session.isAdmin, categories: await getCategoriesNav()});

    } catch (error) {
        console.error('Error retrieving user for editing:', error);
        res.status(500).send('Error retrieving user');
    }
});

router.post('/updateUser/:id', async (req, res) => {
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

router.post('/deleteUser/:id', async (req, res) => {
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

router.get('/featuredItems', async (req, res) => {
    try {
        const productsCollection = database.db(MONGODB_DATABASE).collection('listing_items');
        const featuredItems = await productsCollection.find({ isFeatureItem: true }).toArray();
        res.render('featuredItems', { listings: featuredItems });
    } catch (error) {
        console.error('Failed to fetch featured items:', error);
        res.status(500).send('Error fetching featured items');
        res.render('featuredItems', { listings: [] });
    }
});

router.get('/categoryManagement', async (req, res) => {
    const categoriesArray = await categoryCollection.find().toArray();
    res.render('categoryManagement', {
        categories: categoriesArray
    });
})

router.get('/editCategory/:id', async (req, res) =>
{
    try
    {
        const category = await categoryCollection.findOne({ _id: new ObjectId(req.params.id) });
        res.render('editCategory', { category, isAdmin: req.session.isAdmin, isLoggedIn : req.session.loggedIn, categories: await getCategoriesNav()});
    }
    catch (error)
    {
        console.error('Error retrieving category for editing:', error);
        res.status(500).send('Error retrieving category');
    }
})

router.post('/updateCategory/:id', async (req, res) => {
    try {
        const { name, sub_categories } = req.body;
        console.log(`${name} and ${sub_categories}`)
        await categoryCollection.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: {
                    category_type: name,
                    sub_categories: sub_categories.split(", ")
                }}
        );
        res.redirect('/manage');
    } catch (error) {
        console.error('Error updating category:', error);
        res.status(500).send('Failed to update category');
    }
})

router.post('/deleteCategory/:id', async (req, res) => {
    try {
        const result = await categoryCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if(result.deletedCount === 1) {
            res.status(200).send('Category deleted successfully');
        } else {
            res.status(404).send('Category not found');
        }
    } catch (error) {
        console.error('Failed to delete user:', error);
        res.status(500).send('Failed to delete user');
    }
})

router.post('/addCategory', async (req, res) => {
    const { category_name, sub_categories} = req.body;
    try {
        await categoryCollection.insertOne({ category_type: category_name, sub_categories: sub_categories.split(", ")});
        res.redirect('/manage');

    } catch (error) {
        console.error('Error adding new category:', error);
        res.status(500).send('Failed to add new user');
    }
});

router.post('/load-subcategory', async (req, res) => {

    const type = req.body.categoryType.replace(/"/g, '');
    const {sub_categories} = await categoryCollection.findOne({category_type: type});
    try{
        req.session.save(err => {
            if (err) {
                console.error('Error saving session:', err);
                return res.json({ success: false, message: 'Error saving session' });
            }
            res.json({ success: true, subCategories: sub_categories });
        });
    }catch (error)
    {
        console.error('Failed to remove item from cart:', error);
        res.json({ success: false, message: 'Error removing item from cart' });
    }
})
module.exports = router;