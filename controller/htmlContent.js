// Set up variables + imports
const {categoryCollection} = require('../database/constants')

/**
 * Creates the accordion html code for the left filter sections in the landing page.
 * @param maxVal a number, the maximum value of the listings
 * @param minVal a number, the minimum value of the listings
 * @param currentPrice a number, the price chosen
 * @param subCategories a list of sub-categories depends on the current category
 * @returns a list, contained with HTML code, used to display the filters accordions on the left section in the landing page.
 */
function getBodyFilters(maxVal, minVal, currentPrice, subCategories, categories)
{
    if (maxVal == null || minVal == null)
    {
        maxVal = 0;
        minVal = 0;
        currentPrice = 0;
    }

    let minCalculation = (Math.floor(minVal / 5) * 5);
    let maxCalculation = (Math.ceil(maxVal / 5) * 5);

    if (currentPrice > maxVal)
        currentPrice = maxCalculation / 2;

    let categoriesBody;
    let subcategoriesBody = categoriesBody = "<ul class=\"list-group list-group-flush\">";

    // for each subCategories on that array, assign it as a list element on the sub-category filter on the left
    // since some of them are spaces, we split the spaces and join them with '_'
    subCategories.forEach(function(subC) {
        subcategoriesBody+="<li class=\"list-group-item\"><form method='post' action='/filter/subcategory=" + subC.split(" ").join("_") + "'><button " +
            "style='background: none; border: none'" +
            " type='submit'>" + subC + "</button></form></li>"
    })
    subcategoriesBody+="</ul>";

    categories.forEach(function(C) {
        categoriesBody+="<li class=\"list-group-item\"><form method='post' action='/filter/category=" + C.category_type.split(" ").join("_") + "'><button " +
            "style='background: none; border: none'" +
            " type='submit'>" + C.category_type + "</button></form></li>"
    })
    return [
        categoriesBody,
        subcategoriesBody,
        "<ul class='list-group list-group-flush'>" +
        " <li class='list-group-item'><form method='post' action='/filter/sortby=default'><button style='background: none; border: none' type='submit'>Sort by Default</button></form></li>" +
        " <li class='list-group-item'><form method='post' action='/filter/sortby=ascending'><button style='background: none; border: none' type='submit'>Sort by Lowest Price</button></form></li>" +
        " <li class='list-group-item'><form method='post' action='/filter/sortby=descending'><button style='background: none; border: none' type='submit'>Sort by Highest Price</button></form></li>",
        "<div class=\"row col-sm\">\n" +
        "        <div class=\"col text-start\">\n" +
        "            <label for=\"priceRange\" class=\"form-label\">" +
        "               <strong>$" + minCalculation + "</strong>" +
        "           </label>\n" +
        "        </div>\n" +
        "        <div class=\"col text-middle\">\n" +
        "            <label id=\"userRange\" for=\"priceRange\" class=\"form-label\">$" + currentPrice + "</label>\n" +
        "        </div>\n" +
        "        <div class=\"col text-end\">\n" +
        "            <label for=\"priceRange\" class=\"form-label\">" +
        "               <strong>$" + maxCalculation + "</strong>" +
        "           </label>\n" +
        "        </div>\n" +
        "        <input id=\"selectedPrice\" type=\"range\" class=\"form-range\" min=" + minCalculation + " max=" + maxCalculation + " step=5 id=\"priceRange\" oninput=\"" +
        "{document.getElementById('userRange').innerHTML = `$${this.value}`;}\">\n" +
        "</div>"
    ];
}

/**
 * Get the categories which will be used to display on the nav bar
 * @returns an array of categories.
 */
async function getCategoriesNav()
{
    return await categoryCollection.find({}).toArray();
}

// Export the functions
module.exports =
{
    getBodyFilters,
    getCategoriesNav
}