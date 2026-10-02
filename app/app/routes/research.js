const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

const QUOTE_BASE_URL = "https://finance.yahoo.com/quote/";
const STOCK_SYMBOL_RE = /^[A-Za-z0-9.^-]{1,12}$/;

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {

        if (req.query.symbol) {
            // Fix for A10 Server-Side Request Forgery (CWE-918): the server
            // used to fetch whatever "url" the request supplied, so anyone
            // could make it call internal services. The base URL is now fixed
            // on the server and the symbol must look like a stock ticker.
            const symbol = String(req.query.symbol).trim();
            if (!STOCK_SYMBOL_RE.test(symbol)) {
                return res.status(400).send("Invalid stock symbol");
            }
            const url = QUOTE_BASE_URL + encodeURIComponent(symbol);
            return needle.get(url, (error, newResponse, body) => {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;
