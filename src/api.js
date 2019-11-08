const https = require("https");
const jwt = require("jsonwebtoken");
const querystring = require("querystring");

const JWT_SECRET = process.env.JWT_SECRET;
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;

const fetch = (url, options) => {
  return new Promise((resolve, reject) => {
    https
      .request(url, options, response => {
        let body = "";
        response.on("data", x => body += x);
        response.on("end", () => resolve({ statusCode: response.statusCode, body: body }));
      })
      .end(options.body);
  });
};

const ownerIs = (owner, json) => {
  return json.fields
    ? json.fields.Owner == owner
    : json.records.every(x => x.fields.Owner == owner);
}

const authorize = (token, event, report, callback) => {
  switch (event.httpMethod.toUpperCase()) {
    case "GET":
      event.queryStringParameters["filterByFormula"] = "Owner = '" + token.sub + "'";
      return callback();

    case "POST":
      if (ownerIs(token.sub, JSON.parse(event.body)))
        return callback();
      else
        throw new Error("UNAUTHORIZED");

    default:
      throw new Error("UNAUTHORIZED");
  }
};

const proxy = (event, callback) => {
  const report = err => {
    console.log(err, event);
    callback({ statusCode: 401, body: "" });
  }
  try {
    const bearer = event.headers.authorization.slice("Bearer ".length);
    const token = jwt.verify(bearer, JWT_SECRET, { algorithms: ["HS256"] });
    authorize(token, event, report, () => {
      const url = "https://api.airtable.com/v0/"
        + AIRTABLE_BASE_ID
        + "/"
        + event.headers["x-airtable-table"]
        + "?"
        + querystring.stringify(event.queryStringParameters);
      const options = {
        method: event.httpMethod,
        body: event.body,
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + AIRTABLE_API_KEY,
        },
      };
      fetch(url, options).then(response => callback(response));
    });
  } catch (err) {
    report(err);
  }
};

exports.proxy = proxy;
exports.handler = (event, context, callback) => proxy(event, x => callback(null, x));
