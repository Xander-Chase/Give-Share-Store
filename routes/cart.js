// Set up variables + imports
require('dotenv').config();
const express = require("express");
const {getCategoriesNav} = require("../controller/htmlContent");
const {ObjectId} = require("mongodb");
const {database} = require("../database/constants");
const router = express.Router();

const mongodb_database = process.env.MONGODB_DATABASE;

// Route for navigating the cart view
router.get('/', async (req, res) => {
    const cartItems = req.session.cart || [];
    res.render('cartView', {
        isLoggedIn: req.session.loggedIn,
        items: cartItems,
        paypalClientId: process.env.PAYPAL_CLIENT_ID,
        isAdmin: req.session.isAdmin || false
    });
});

// Post method on handling adding to a cart
router.post('/add-to-cart', async (req, res) => {
    const itemId = req.body.itemId;
    try {
        const productsCollection = database.db(mongodb_database).collection('listing_items');
        const item = await productsCollection.findOne({ _id: ObjectId.createFromHexString(itemId) });

        if (item) {
            req.session.cart.push(item);
            req.session.save(err => {
                if (err) {
                    console.error('Error saving session:', err);
                }
                res.json({ success: true, cartItemCount: req.session.cart.length });
            });
        } else {
            res.json({ success: false, message: 'Item not found' });
        }
    } catch (error) {
        console.error('Failed to add item to cart:', error);
        res.json({ success: false, message: 'Error adding item to cart' });
    }
});

// Post method on handling removing from the cart
router.post('/remove-from-cart', async (req, res) => {
    const itemId = req.body.itemId;

    try {
        if (!req.session.cart) {
            return res.json({ success: false, message: 'Cart is empty' });
        }

        req.session.cart = req.session.cart.filter(item => item._id.toString() !== itemId);
        req.session.save(err => {
            if (err) {
                console.error('Error saving session:', err);
                return res.json({ success: false, message: 'Error saving session' });
            }
            res.json({ success: true, cartItemCount: req.session.cart.length });
        });
    } catch (error) {
        console.error('Failed to remove item from cart:', error);
        res.json({ success: false, message: 'Error removing item from cart' });
    }
});

// Export the router
module.exports = router;