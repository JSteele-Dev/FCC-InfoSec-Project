const express = require('express');
const app = express();

// "import helmet to file"
const helmet = require('helmet');

// Hides or Removes X-Powered-By header from the request
app.use(helmet.hidePoweredBy());

// Restricts who can place the site in a Frame, has 3 modes: DENY, SAMEORIGIN AND ALLOW-FROM
app.use(helmet.frameguard(
  {action: 'deny'}
));

// Basic protection from XSS attacks
app.use(helmet.xssFilter());

// Instructs browser to not bypass the provided Content-Type
app.use(helmet.noSniff());

// Prevents IE users from executing downloads in trusted site context
app.use(helmet.ieNoOpen());

// HTTP Strict Transport Security
// Policy that protects against protocol downgrade attacks and cookie hijacking
const timeInSeconds = 90*24*60*60; // 90 Days in seconds
app.use(helmet.hsts(
  {maxAge: timeInSeconds, force: true} // force is only being used for this project
));
// Note: Configuring HTTPS on a custom website requires SSL/TLS Certificates 
// and acquisition of a Domain.

// Fetches DNS records for the links in a page, can improve performance
// May lead to DNS service over-use, privacy issues and page statitics alteration
app.use(helmet.dnsPrefetchControl()); // Disables Prefetch

// Tries to disable caching in clients browser.
app.use(helmet.noCache());

// Prevents injections of unintended scriptsXSS vulnerabilities, undesired tracking,
// malicious frames, and more.
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"], // fallback directive
      scriptSrc: ["'self'", 'trusted-cdn.com'], // Only allow scripts to be downloaded from site and specific domains.
    }
  })
);

// app.use(helmet()) automatically includes the above middleware except noCache and CSP
// The 'parent' helmet() middleware is easy to implement in a real project


module.exports = app;
const api = require('./server.js');
app.use(express.static('public'));
app.disable('strict-transport-security');
app.use('/_api', api);
app.get("/", function (request, response) {
  response.sendFile(__dirname + '/views/index.html');
});
let port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Your app is listening on port ${port}`);
});
