const url = require("url");
const api = require("./api");

require("http").createServer((request, response) => {
  let body = "";
  request.on("data", x => body += x);
  request.on("end", () => {
    const event = {
      httpMethod: request.method,
      headers: request.headers,
      queryStringParameters: url.parse(request.url, true).query,
      body: body,
    };
    api.proxy(event, x => {
      response.statusCode = x.statusCode;
      response.end(x.body);
    });
  });
}).listen(process.env.PORT || 3000);
