// Set up variables + imports
const express = require('express');
const router = express.Router();

/**
 * Reset the categories and sub-categories.
 * @param req request session used to clear.
 */
function ResetCategoryFilter(req)
{
    req.session.category = null;
    req.session.subcategory = null;
}

// Post method on handling search input when empty
router.post('/keyword=', (req, res) => {
    req.session.keyword = null;
    ResetCategoryFilter(req);
    req.session.maxPrice = 0;
    res.redirect('/');
})

// Post method on handling search input when filled
router.post('/keyword=:key',  (req, res) => {
    req.session.keyword = req.params.key;
    ResetCategoryFilter(req);
    req.session.maxPrice = 0;
    res.redirect('/');
});

// Post method on handling changing the maximum price
router.post('/price=:newMax', (req, res) => {
    req.session.maxPrice = req.params.newMax;
    res.redirect('/');
})

// Post method on choosing a category
router.post('/category=:type',  (req, res) => {
    req.session.category = req.params.type;
    req.session.subcategory = null;
    req.session.keyword = null;
    res.redirect('/');
})

// Post method on choosing an empty category
router.post('/category=',  (req, res) => {
    ResetCategoryFilter(req);
    req.session.keyword = null;
    res.redirect('/');
})

// Post method on choosing a sub-category
router.post('/subcategory=:type',  (req, res) => {
    req.session.subcategory = req.params.type.split("_").join(" ");
    res.redirect('/');
})

// Post method on handing on picking a sorting filter
router.post('/sortby=:option', async (req, res) => {
    req.session.sortBy = req.params.option;
    res.redirect('/');
})

// Post method on clearing filters
router.post('/clear', (req, res) =>
{

    req.session.maxPrice = 0;
    req.session.keyword = null;
    ResetCategoryFilter(req);
    req.session.sortBy = 'default';
    res.redirect('/');
})

// Get method on clearing filters. This is used for elements that are hyperlinks, such as the logo on the search navbar.
router.get('/clear', (req, res) =>
{

    req.session.maxPrice = 0;
    req.session.keyword = null;
    ResetCategoryFilter(req);
    req.session.sortBy = 'default';
    res.redirect('/');
})
// Export router
module.exports = router;