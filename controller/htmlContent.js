const {categoryCollection} = require('../database/constants')



function getBodyFilters(maxVal, minVal, currentPrice, subCategories)
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

    let categoriesBody =
        "<ul class=\"list-group list-group-flush\">";

    // for each subCategories on that array, assign it as a list element on the sub-category filter on the left
    // since some of them are spaces, we split the spaces and join them with '_'
    subCategories.forEach(function(subC) {
        categoriesBody+="<li class=\"list-group-item\"><form method='post' action='/filter/subcategory=" + subC.split(" ").join("_") + "'><button " +
            "style='background: none; border: none'" +
            " type='submit'>" + subC + "</button></form></li>"
    })
    categoriesBody+="</ul>";
    return [

        categoriesBody,
        "<ul class='list-group list-group-flush'>" +
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

async function getCategoriesNav()
{
    return await categoryCollection.find({}).toArray();

}

module.exports =
{
    getBodyFilters,
    getCategoriesNav
}