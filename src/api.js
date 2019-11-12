const https = require("https");
const jwt = require("jsonwebtoken");
const querystring = require("querystring");
const util = require("util");

const JWT_SECRET = process.env.JWT_SECRET;
const AIRTABLE_API_KEY = process.env.AIRTABLE_API_KEY;
const AIRTABLE_BASE_ID = process.env.AIRTABLE_BASE_ID;
const AIRTABLE_OWNER_TABLE_NAME = process.env.AIRTABLE_OWNER_TABLE_NAME;

const request = (path, options) => {
  const url = "https://api.airtable.com/v0/" + AIRTABLE_BASE_ID + "/" + path;
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

const authIf = (event, check) => {
  return check ? Promise.resolve(event) : Promise.reject(401);
};

const precheck = (owner, event, recordIds) => {
  return request(AIRTABLE_OWNER_TABLE_NAME + "/" + owner, { method: "GET" }).then(response => {
    const all = JSON.parse(response.body).fields[event.headers["x-airtable-path"]];
    return authIf(event, recordIds.every(id => all.includes(id)));
  });
};

const ownerIs = (owner, json) => {
  return json.fields
    ? json.fields.Owner == owner
    : json.records.every(x => x.fields.Owner == owner);
};

const authorize = (token, event) => {
  switch (event.httpMethod.toUpperCase()) {
    case "GET":
      event.queryStringParameters.filterByFormula = "Owner = '" + token.sub + "'";
      return Promise.resolve(event);
    case "POST":
      return authIf(event, ownerIs(token.sub, JSON.parse(event.body)));
    case "PATCH":
      return precheck(token.sub, event, JSON.parse(event.body).records.map(x => x.id));
    case "DELETE":
      const ids = event.queryStringParameters["records[]"];
      return precheck(token.sub, event, Array.isArray(ids) ? ids : [ids]);
    default:
      return Promise.reject(405);
  }
};

const relay = event => {
  const path = event.headers["x-airtable-path"]
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
      callback({ statusCode: isNaN(err) ? 400 : err, body: "" });
    });
};

exports.proxy = proxy;
exports.handler = (event, _, callback) => proxy(event, x => callback(null, x));
