const express = require('express');
const router = express.Router();

function ResetCategoryFilter(req)
{
    req.session.category = null;
    req.session.subcategory = null;
}

router.post('/keyword=', (req, res) => {
    req.session.keyword = null;
    ResetCategoryFilter(req);
    req.session.maxPrice = 0;
    res.redirect('/');
})

router.post('/keyword=:key',  (req, res) => {
    req.session.keyword = req.params.key;
    ResetCategoryFilter(req);
    req.session.maxPrice = 0;
    res.redirect('/');
});

router.post('/price=:newMax', (req, res) => {
    req.session.maxPrice = req.params.newMax;
    res.redirect('/');
})

router.post('/category=:type',  (req, res) => {
    req.session.category = req.params.type;
    req.session.subcategory = null;
    req.session.keyword = null;
    res.redirect('/');
})

router.post('/category=',  (req, res) => {
    ResetCategoryFilter(req);
    req.session.keyword = null;
    res.redirect('/');
})

router.post('/subcategory=:type',  (req, res) => {
    req.session.subcategory = req.params.type.split("_").join(" ");
    res.redirect('/');
})

router.post('/sortby=:option', async (req, res) => {
    req.session.sortBy = req.params.option;
    res.redirect('/');
})

router.post('/clear', (req, res) =>
{

    req.session.maxPrice = 0;
    req.session.keyword = null;
    ResetCategoryFilter(req);
    req.session.sortBy = 'ascending';
    res.redirect('/');
})


module.exports = router;