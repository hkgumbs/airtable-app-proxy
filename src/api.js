const https = require("https");
const jwt = require("jsonwebtoken");
const querystring = require("querystring");
const util = require("util");

const JWT_SECRET = process.env.JWT_SECRET;
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;

const request = (path, options) => {
  const url = "https://api.airtable.com/v0/" + AIRTABLE_BASE_ID + path;
  options.headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + AIRTABLE_API_KEY,
  };
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

const authorize = (token, event) => {
  switch (event.httpMethod.toUpperCase()) {
    case "GET":
      event.queryStringParameters.filterByFormula = "Owner = '" + token.sub + "'";
      return Promise.resolve(event);

    case "POST":
      return ownerIs(token.sub, JSON.parse(event.body))
        ? Promise.resolve(event)
        : Promise.reject(new Error("Unauthorized"));

    case "PATCH":
    case "DELETE":
      // TODO
      return request("/", { method: "GET" });

    default:
      return Promise.reject(new Error("Unauthorized"));
  }
};

const relay = event => {
  const path = "/"
    + event.headers["x-airtable-path"]
    + "?"
    + querystring.stringify(event.queryStringParameters);
  return request(path, { method: event.httpMethod, body: event.body });
};

const proxy = (event, callback) => {
  const authorization = event.headers.authorization || "";
  const bearer = authorization.slice("Bearer ".length);
  util.promisify(jwt.verify)(bearer, JWT_SECRET, { algorithms: ["HS256"] })
    .then(token => authorize(token, event))
    .then(newEvent => relay(newEvent))
    .then(response => callback(response))
    .catch(err => {
      console.log(err, event);
      callback({ statusCode: 401, body: "" });
    });
};

exports.proxy = proxy;
exports.handler = (event, _, callback) => proxy(event, x => callback(null, x));
