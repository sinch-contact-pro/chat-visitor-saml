const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
// jwt tokens for modern stateless tokens
const jwt = require('jsonwebtoken');
//import dateFormat from "dateformat";
const date = require('date-and-time')
// passport and saml to handle authentication mechanism
const passport = require('passport');
const saml = require('passport-saml');
const bodyParser = require('body-parser');
// express session and cookieparser are used to handle session cookies
const session = require('express-session');
const cookieParser = require('cookie-parser');
//javascript stringify component to make javascript templating bit easier
const jsStringify = require('js-stringify');
//public and private keys for JWT tokens
var publicKey = fs.readFileSync('./public.pem');
var privateKey = fs.readFileSync('./private.pem');
//saml metadata certs
var signCert = fs.readFileSync('./certs/cert.pem', 'utf8');
var encryptCert = fs.readFileSync('./certs/cert.pem', 'utf8');
//SSL certificates and keys
// var siteCert = fs.readFileSync('./certs/sitecert.crt', 'utf8');
// var siteKey = fs.readFileSync('/Users/vilsal/Documents/keys/sapcctr_site.key', 'utf8');
// var certs = {key: siteKey, cert: siteCert};
//const session = require('cookie-session')

const WebSocket = require('faye-websocket')

const dotenv = require('dotenv').config();

//configurations should be provided via process env or using .env config file 
const port = process.env.PORT;
const apigwdomain = process.env.apigwdomain || "login-eu-c1.cc.sinch.com";
const apigwproxytarget = process.env.apigwproxytarget || 'https://login-eu-c1.cc.sinch.com/standarddemo/visitor/'
const cc365domain = process.env.cc365domain;
const apikey = process.env.apikey || "TLgUIdEVBH2VgXKBxjDil96NUnDb7XeE90HR4BW2";
const appsessionsecret =  process.env.cookiesecret || 'my-secret-key-anything-goes-for-test';
const samlentrypoint = process.env.samlentrypoint || 'http://simplesaml.dev.cc.sinch.com:8080/simplesaml/saml2/idp/SSOService.php';
const samlissuer = process.env.samlissuer || 'saml-poc';
const originheader = process.env.originheader || 'https://voicext.dev.cc.sinch.com/'
const samlprivatecert = process.env.samlprivatecert || '/certs/key.pem'
const samldecryptionkey = process.env.samldecryptionkey || '/certs/key.pem'
const siteCertFilePath = process.env.sitecertfile
const siteCertKeyFilePath =  process.env.sitecertkeyfile 
const proxytarget = 'https://login-eu-c1.cc.sinch.com/standarddemo/'
const samlcallbackurl = process.env.samlcallbackurl || 'https://voicext.dev.cc.sinch.com/login/callback'


const { createProxyServer } = require('http-proxy');

//cookie parsing helper
const parseCookie = str =>
  str
    .split(';')
    .map(v => v.split('='))
    .reduce((acc, v) => {
      acc[decodeURIComponent(v[0].trim())] = decodeURIComponent(v[1].trim());
      return acc;
    }, {});


// proxy is used to capture all client trafic
var proxy = createProxyServer({ target: proxytarget, ws: true, secure: false });

// in case we want to route thru apigateway we can use separate apigwproxy target
var apigwproxy = createProxyServer({ target: apigwproxytarget, ws: false, secure: false});
var app = express();

//lets setup saml strategy for this server
var samlStrategy = new saml.Strategy({
    callbackUrl: samlcallbackurl,
    entryPoint: samlentrypoint,
    issuer: samlissuer,
    identifierFormat: null,
    validateInResponseTo: false,
    disableRequestedAuthnContext: true,
    privateCert: fs.readFileSync(__dirname + samlprivatecert, 'utf8'),
    decryptionPvk: fs.readFileSync(__dirname + samldecryptionkey, 'utf8')
  }, function(profile, done) {
      return done(null, profile);
  });

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

app.use(session({secret: appsessionsecret, 
                 resave: false, 
                 saveUninitialized: true,
                 cookie: { secure: true }
                }));

// keep static files in pub folder
app.use(express.static('pub'))
app.use(passport.initialize({}));
app.use(passport.session({}));
var expiryDate = new Date(Date.now() + 60 * 60 * 1000) // 1 hour

// using SAML strategy with passport
passport.use('samlStrategy', samlStrategy);

passport.serializeUser(function(user, done) {    
    console.log('<<< serialize user >>>');
    console.log(user);    
    console.log('----------------------');    
    done(null, user);
});

 passport.deserializeUser(function(user, done) {
    console.log('<<< deserialize user >>>');
    console.log(user);
    console.log('----------------------');
    done(null, user);
});
                
// using pug as view engine
app.set('view engine', 'pug')

// default test route
app.get('/', function(req, res) {
    res.render('index', { title: 'Hello there ', 
    message: 'Hello there  ' + req.session.email, 
    idtoken: '', 
    useremail: req.session.email, 
    jsStringify: jsStringify
    })
});

// login route
app.get('/login',
    function (req, res, next) {
        req.session.email = ""
        console.log('<<< Start login handler >>>');
        next();
    },
    passport.authenticate('samlStrategy'),
);

//login callback route
app.post('/login/callback',
    function (req, res, next) {
        console.log('<<< Start login callback >>>');
        next();
    },
    passport.authenticate('samlStrategy'),
    function (req, res) {
        //res.setHeader('Set-Cookie','visited=true; Max-Age=3000; HttpOnly, Secure');
        // using jwt sign to create user identity token for chat
        let now =  new Date();
        let nowDate = date.format(now, "dddd, mmmm dS, yyyy, h:MM:ss TT");
        console.log('logged in user ' + req.user.email + ' ' + nowDate);
        req.session.email = req.user.email        
        jwt.sign({  email: req.user.email, iat: Date.now(), iss: "www.saml-poc.com", friendlyiat: nowDate },
                    privateKey, { algorithm: 'RS256' },
                    function(err, token) {
                        console.log("<<<< user JWT token >>>>");
                        console.log(token)
                        //lets set JWT token into cookie
                        res.cookie('JWT',token, { maxAge: 900000, httpOnly: true })     
                        // render page with pug (index.pug) and render result as response to client
                        res.render('index', { title: 'Login success', 
                                              message: 'Successfully logged in, user email> ' + req.user.email, 
                                              idtoken: token, 
                                              useremail: req.user.email, 
                                              jsStringify: jsStringify
                                            }
                        );
                }
            );
        }
);

// https server is required for SAML to work. However if we have intermediate loadbalancer serving HTTPS then we can use plain HTTP towards backend
var server = require('http').createServer(app);
// https server setup comment out next line -->
// var server = require('https').createServer(certs, app);

//setting up required backend headers
apigwproxy.on('proxyReq', function(proxyReq, req, res, options) {
    //we need to re-write host header when proxying
    proxyReq.setHeader('Host', apigwdomain);
    proxyReq.setHeader('x-api-key', apikey);
  });

//catch possible proxying errors
apigwproxy.on('error', function(e){
    console.log(e)
});  
  
//this is the backend authentication endpoint route
app.post('/standarddemo/visitor/ecfs/authentication', function(req, res) {
    //lets check that user has an existing session otherwise respond unauthorized
    if (req.session.email) {
        apigwproxy.web(req, res, {});
    } else { 
        console.log("Unauthorized user");        
        res.sendStatus(401) 
    }  
});

//catch possible proxying errors
proxy.on('error', function(e){
    console.log(e)
});  

//this is route for app get and post
function visitorwebhandler (req, res) {
    console.log("proxying web request to backend", req.url);
    proxy.web(req, res, {});
}

//proxy all other gets and posts
app.get('/standarddemo/visitor/ecf/*', visitorwebhandler)
app.post('/standarddemo/visitor/ecf/*', visitorwebhandler)

// websocket proxying
server.on('upgrade', function(request, socket, body) {     
    console.log("at upgrade")
    if (WebSocket.isWebSocket(request)) {                    
        let cookiesObj = parseCookie(request.headers.cookie)
        console.log(request.headers) 
        if (cookiesObj.JWT){ 
            //verify JWT
            let decoded = jwt.verify(cookiesObj.JWT, publicKey);  
            if (decoded.email){  
                let frontend = new WebSocket(request, socket, body);
                let heads = {
                    'Origin': originheader,
                    'Content-Type': 'application/json',
                    'Cookie': request.headers.cookie					
                }
            
                //request url should contain the path with request params
                let wssuri = "wss://prod-eu.sapcctr.com/" + request.url
                let backend = new WebSocket.Client(wssuri,[],{headers: heads});
  
                backend.on('message', function(event) {       
                    console.log("<- ", event.data);                    
                    try {
                        // there may be a raise condition when backend sends stuff
                        // but frontend is nullified already (try catch handles that)
                        frontend.send(event.data);
                    } catch (e) {
                        console.log("cannot send to frontend")   
                        console.log(e)
                    }
                    
                });
      
                backend.on('close', function(event) {                    
                    console.log('Upstream close ', event.code, event.reason);     
                    frontend = null;
                    backend = null;   
                });

                backend.on('error', function(error) {  
                    console.error(error.message);
                });
  
                frontend.on('message', function(event) {
                    //message handling from client
                    console.log("-> ",event.data);                        
                    try {
                        let msg = JSON.parse(event.data)
                        if (msg.hasOwnProperty('method') && msg.hasOwnProperty('uri') && msg.hasOwnProperty('body')){
                            //console.log("try to set the correct email address " >> decoded.email)                                
                            if (msg.uri == '/users/me/properties' && msg.method =='PUT'){
                                msg.body.chat_address = decoded.email
                                msg.body.alias = '' //we could set some alias here as well if we have some e.g. userid
                            }   
                        }
                        
                        backend.send(JSON.stringify(msg));                                                 
                    } catch (e) {
                        console.log("not valid json string or sending failed")          
                    } //end try catch           
                });
      
                frontend.on('close', function(event) {
                    console.log('Downstream close ', event.code, event.reason);
                    backend = null;
                    frontend = null;
                });

                frontend.on('error', function(error) {  
                    console.error(error.message);
                });
            }// end if decoded.email
        }// end if JWT             
    }//end if Websocket
});

// metadata route
app.get('/metadata',
    function(req, res) {
        res.type('application/xml'); 
        res.status(200).send(
            // add certificate for sign and encrypt (thus 2 times certificate)
            samlStrategy.generateServiceProviderMetadata(
                fs.readFileSync(__dirname + '/certs/cert.pem', 'utf8'), 
                signCert, 
                encryptCert
            )
        );
    }
);

// verify token
app.get('/verify',
    function(req, res) {
        
        jwt.verify(req.query.token, publicKey, function(err, decoded) {
            console.log(decoded.email)
            console.log(decoded.iat)
            console.log(decoded.friendlyiat)
            res.render('verify', { title: 'Login success', 
                                   message: 'Verified token> ' + decoded.email, 
                                   useremail: decoded.email,
                                   iat: decoded.friendlyiat,
                                   iss: decoded.iss, 
                                   jsStringify: jsStringify
                                 }
            );
         }
        );
    }
);

// verify token REST
app.get('/verify.json',
    function(req, res) {
        
        jwt.verify(req.query.token, publicKey, function(err, decoded) {
            console.log(decoded.email)
            console.log(decoded.iat)
            console.log(decoded.friendlyiat)
            res.type('application/json'); 
            res.status(200).send({email: decoded.email, friendlyiat: decoded.friendlyiat, issuer: decoded.iss});
        }
        );
    }
);

// server listening
server.listen(port, function () {
    console.log('Listening on port %d', server.address().port)       
});
