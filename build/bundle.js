module.exports =
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "/build/";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	var async = __webpack_require__(1);
	var AWS = __webpack_require__(2);
	var express = __webpack_require__(3);
	var memoizer = __webpack_require__(4);
	var moment = __webpack_require__(7);
	var Request = __webpack_require__(8);
	var useragent = __webpack_require__(9);
	var Webtask = __webpack_require__(10);

	var app = express();

	function lastLogCheckpoint(req, res) {
	  var ctx = req.webtaskContext;
	  var required_settings = ['AUTH0_DOMAIN', 'AUTH0_CLIENT_ID', 'AUTH0_CLIENT_SECRET', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_BUCKET_NAME'];
	  var missing_settings = required_settings.filter(function (setting) {
	    return !ctx.data[setting];
	  });

	  if (missing_settings.length) {
	    return res.status(400).send({ message: 'Missing settings: ' + missing_settings.join(', ') });
	  }

	  // If this is a scheduled task, we'll get the last log checkpoint from the previous run and continue from there.
	  req.webtaskContext.storage.get(function (err, data) {

	    var startCheckpointId = typeof data === 'undefined' ? null : data.checkpointId;

	    AWS.config.update({
	      accessKeyId: ctx.data.AWS_ACCESS_KEY_ID,
	      secretAccessKey: ctx.data.AWS_SECRET_ACCESS_KEY,
	      region: ctx.data.AWS_REGION || 'us-west-2'
	    });
	    var s3 = new AWS.S3({ apiVersion: '2006-03-01' });

	    // Start the process.
	    async.waterfall([function (callback) {
	      var getLogs = function getLogs(context) {
	        console.log('Logs from: ' + (context.checkpointId || 'Start') + '.');

	        var take = Number.parseInt(ctx.data.BATCH_SIZE || 100);

	        take = Math.min(100, take);

	        context.logs = context.logs || [];

	        getLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, context.checkpointId, function (logs, err) {
	          if (err) {
	            console.log('Error getting logs from Auth0', err);
	            return callback(err);
	          }

	          if (logs && logs.length) {
	            logs.forEach(function (l) {
	              return context.logs.push(l);
	            });
	            context.checkpointId = context.logs[context.logs.length - 1]._id;
	          }

	          console.log('Total logs: ' + context.logs.length + '.');
	          return callback(null, context);
	        });
	      };

	      getLogs({ checkpointId: startCheckpointId });
	    }, function (context, callback) {
	      context.logs = context.logs.map(function (record) {
	        var level = 0;
	        record.type_code = record.type;
	        if (logTypes[record.type]) {
	          level = logTypes[record.type].level;
	          record.type = logTypes[record.type].event;
	        }

	        var agent = useragent.parse(record.user_agent);
	        record.os = agent.os.toString();
	        record.os_version = agent.os.toVersion();
	        record.device = agent.device.toString();
	        record.device_version = agent.device.toVersion();
	        return record;
	      });
	      callback(null, context);
	    }, function (context, callback) {
	      console.log('Uploading logs to S3...');

	      async.eachLimit(context.logs, 5, function (log, cb) {
	        var date = moment(log.date);
	        var url = date.format('YYYY/MM/DD/HH') + '/' + date.toISOString() + '-' + log._id + '.json';
	        console.log('Uploading ' + url + '.');

	        var params = {
	          Bucket: ctx.data.AWS_BUCKET_NAME,
	          Key: url,
	          Body: JSON.stringify(log),
	          ContentType: 'application/json',
	          ServerSideEncryption: 'AES256'
	        };
	        s3.putObject(params, function (err) {
	          return cb(err);
	        });
	      }, function (err) {
	        if (err) {
	          return callback(err);
	        }

	        console.log('Upload complete.');
	        return callback(null, context);
	      });
	    }], function (err, context) {
	      if (err) {
	        console.log('Job failed.', err);

	        return req.webtaskContext.storage.set({ checkpointId: startCheckpointId }, { force: 1 }, function (error) {
	          if (error) {
	            console.log('Error storing startCheckpoint', error);
	            return res.status(500).send({ error: error });
	          }

	          res.status(500).send({
	            error: err
	          });
	        });
	      }

	      console.log('Job complete.');
	      return req.webtaskContext.storage.set({ checkpointId: context.checkpointId, totalLogsProcessed: context.logs.length }, { force: 1 }, function (error) {
	        if (error) {
	          console.log('Error storing checkpoint', error);
	          return res.status(500).send({ error: error });
	        }

	        res.sendStatus(200);
	      });
	    });
	  });
	}

	var logTypes = {
	  's': {
	    event: 'Success Login',
	    level: 1 // Info
	  },
	  'seacft': {
	    event: 'Success Exchange',
	    level: 1 // Info
	  },
	  'seccft': {
	    event: 'Success Exchange (Client Credentials)',
	    level: 1 // Info
	  },
	  'feacft': {
	    event: 'Failed Exchange',
	    level: 3 // Error
	  },
	  'feccft': {
	    event: 'Failed Exchange (Client Credentials)',
	    level: 3 // Error
	  },
	  'f': {
	    event: 'Failed Login',
	    level: 3 // Error
	  },
	  'w': {
	    event: 'Warnings During Login',
	    level: 2 // Warning
	  },
	  'du': {
	    event: 'Deleted User',
	    level: 1 // Info
	  },
	  'fu': {
	    event: 'Failed Login (invalid email/username)',
	    level: 3 // Error
	  },
	  'fp': {
	    event: 'Failed Login (wrong password)',
	    level: 3 // Error
	  },
	  'fc': {
	    event: 'Failed by Connector',
	    level: 3 // Error
	  },
	  'fco': {
	    event: 'Failed by CORS',
	    level: 3 // Error
	  },
	  'con': {
	    event: 'Connector Online',
	    level: 1 // Info
	  },
	  'coff': {
	    event: 'Connector Offline',
	    level: 3 // Error
	  },
	  'fcpro': {
	    event: 'Failed Connector Provisioning',
	    level: 4 // Critical
	  },
	  'ss': {
	    event: 'Success Signup',
	    level: 1 // Info
	  },
	  'fs': {
	    event: 'Failed Signup',
	    level: 3 // Error
	  },
	  'cs': {
	    event: 'Code Sent',
	    level: 0 // Debug
	  },
	  'cls': {
	    event: 'Code/Link Sent',
	    level: 0 // Debug
	  },
	  'sv': {
	    event: 'Success Verification Email',
	    level: 0 // Debug
	  },
	  'fv': {
	    event: 'Failed Verification Email',
	    level: 0 // Debug
	  },
	  'scp': {
	    event: 'Success Change Password',
	    level: 1 // Info
	  },
	  'fcp': {
	    event: 'Failed Change Password',
	    level: 3 // Error
	  },
	  'sce': {
	    event: 'Success Change Email',
	    level: 1 // Info
	  },
	  'fce': {
	    event: 'Failed Change Email',
	    level: 3 // Error
	  },
	  'scu': {
	    event: 'Success Change Username',
	    level: 1 // Info
	  },
	  'fcu': {
	    event: 'Failed Change Username',
	    level: 3 // Error
	  },
	  'scpn': {
	    event: 'Success Change Phone Number',
	    level: 1 // Info
	  },
	  'fcpn': {
	    event: 'Failed Change Phone Number',
	    level: 3 // Error
	  },
	  'svr': {
	    event: 'Success Verification Email Request',
	    level: 0 // Debug
	  },
	  'fvr': {
	    event: 'Failed Verification Email Request',
	    level: 3 // Error
	  },
	  'scpr': {
	    event: 'Success Change Password Request',
	    level: 0 // Debug
	  },
	  'fcpr': {
	    event: 'Failed Change Password Request',
	    level: 3 // Error
	  },
	  'fn': {
	    event: 'Failed Sending Notification',
	    level: 3 // Error
	  },
	  'sapi': {
	    event: 'API Operation'
	  },
	  'limit_ui': {
	    event: 'Too Many Calls to /userinfo',
	    level: 4 // Critical
	  },
	  'api_limit': {
	    event: 'Rate Limit On API',
	    level: 4 // Critical
	  },
	  'sdu': {
	    event: 'Successful User Deletion',
	    level: 1 // Info
	  },
	  'fdu': {
	    event: 'Failed User Deletion',
	    level: 3 // Error
	  },
	  'fapi': {
	    event: 'Failed API Operation',
	    level: 3 // Error
	  },
	  'limit_wc': {
	    event: 'Blocked Account',
	    level: 3 // Error
	  },
	  'limit_mu': {
	    event: 'Blocked IP Address',
	    level: 3 // Error
	  },
	  'slo': {
	    event: 'Success Logout',
	    level: 1 // Info
	  },
	  'flo': {
	    event: ' Failed Logout',
	    level: 3 // Error
	  },
	  'sd': {
	    event: 'Success Delegation',
	    level: 1 // Info
	  },
	  'fd': {
	    event: 'Failed Delegation',
	    level: 3 // Error
	  }
	};

	function getLogsFromAuth0(domain, token, take, from, cb) {
	  var url = 'https://' + domain + '/api/v2/logs';

	  Request({
	    method: 'GET',
	    url: url,
	    json: true,
	    qs: {
	      take: take,
	      from: from,
	      sort: 'date:1',
	      per_page: take
	    },
	    headers: {
	      Authorization: 'Bearer ' + token,
	      Accept: 'application/json'
	    }
	  }, function (err, res, body) {
	    if (err) {
	      console.log('Error getting logs', err);
	      cb(null, err);
	    } else if (!/^2/.test('' + res.statusCode)) {
	      console.log('Error getting logs', res);
	      cb(null, JSON.stringify(body));
	    } else {
	      cb(body);
	    }
	  });
	}

	var getTokenCached = memoizer({
	  load: function load(apiUrl, audience, clientId, clientSecret, cb) {
	    Request({
	      method: 'POST',
	      url: apiUrl,
	      json: true,
	      body: {
	        audience: audience,
	        grant_type: 'client_credentials',
	        client_id: clientId,
	        client_secret: clientSecret
	      }
	    }, function (err, res, body) {
	      if (err) {
	        cb(null, err);
	      } else if (!/^2/.test('' + res.statusCode)) {
	        cb(null, JSON.stringify(body));
	      } else {
	        cb(body.access_token);
	      }
	    });
	  },
	  hash: function hash(apiUrl) {
	    return apiUrl;
	  },
	  max: 100,
	  maxAge: 1000 * 60 * 60
	});

	app.use(function (req, res, next) {
	  var apiUrl = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/oauth/token';
	  var audience = 'https://' + req.webtaskContext.data.AUTH0_DOMAIN + '/api/v2/';
	  var clientId = req.webtaskContext.data.AUTH0_CLIENT_ID;
	  var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

	  getTokenCached(apiUrl, audience, clientId, clientSecret, function (access_token, err) {
	    if (err) {
	      console.log('Error getting access_token', err);
	      return next(err);
	    }

	    req.access_token = access_token;
	    next();
	  });
	});

	app.get('/', lastLogCheckpoint);
	app.post('/', lastLogCheckpoint);

	module.exports = Webtask.fromExpress(app);

/***/ },
/* 1 */
/***/ function(module, exports) {

	module.exports = require("async");

/***/ },
/* 2 */
/***/ function(module, exports) {

	module.exports = require("aws-sdk");

/***/ },
/* 3 */
/***/ function(module, exports) {

	module.exports = require("express");

/***/ },
/* 4 */
/***/ function(module, exports, __webpack_require__) {

	const LRU        = __webpack_require__(5);
	const _          = __webpack_require__(6);
	const lru_params = [ 'max', 'maxAge', 'length', 'dispose', 'stale' ];

	module.exports = function (options) {
	  const cache      = new LRU(_.pick(options, lru_params));
	  const load       = options.load;
	  const hash       = options.hash;
	  const bypass     = options.bypass;
	  const itemMaxAge = options.itemMaxAge;
	  const loading    = new Map();

	  if (options.disable) {
	    return load;
	  }

	  const result = function () {
	    const args       = _.toArray(arguments);
	    const parameters = args.slice(0, -1);
	    const callback   = args.slice(-1).pop();
	    const self       = this;

	    var key;

	    if (bypass && bypass.apply(self, parameters)) {
	      return load.apply(self, args);
	    }

	    if (parameters.length === 0 && !hash) {
	      //the load function only receives callback.
	      key = '_';
	    } else {
	      key = hash.apply(self, parameters);
	    }

	    var fromCache = cache.get(key);

	    if (fromCache) {
	      return callback.apply(null, [null].concat(fromCache));
	    }

	    if (!loading.get(key)) {
	      loading.set(key, []);

	      load.apply(self, parameters.concat(function (err) {
	        const args = _.toArray(arguments);

	        //we store the result only if the load didn't fail.
	        if (!err) {
	          const result = args.slice(1);
	          if (itemMaxAge) {
	            cache.set(key, result, itemMaxAge.apply(self, parameters.concat(result)));
	          } else {
	            cache.set(key, result);
	          }
	        }

	        //immediately call every other callback waiting
	        loading.get(key).forEach(function (callback) {
	          callback.apply(null, args);
	        });

	        loading.delete(key);
	        /////////

	        callback.apply(null, args);
	      }));
	    } else {
	      loading.get(key).push(callback);
	    }
	  };

	  result.keys = cache.keys.bind(cache);

	  return result;
	};


	module.exports.sync = function (options) {
	  const cache = new LRU(_.pick(options, lru_params));
	  const load = options.load;
	  const hash = options.hash;
	  const disable = options.disable;
	  const bypass = options.bypass;
	  const self = this;
	  const itemMaxAge = options.itemMaxAge;

	  if (disable) {
	    return load;
	  }

	  const result = function () {
	    var args = _.toArray(arguments);

	    if (bypass && bypass.apply(self, arguments)) {
	      return load.apply(self, arguments);
	    }

	    var key = hash.apply(self, args);

	    var fromCache = cache.get(key);

	    if (fromCache) {
	      return fromCache;
	    }

	    const result = load.apply(self, args);
	    if (itemMaxAge) {
	      cache.set(key, result, itemMaxAge.apply(self, args.concat([ result ])));
	    } else {
	      cache.set(key, result);
	    }

	    return result;
	  };

	  result.keys = cache.keys.bind(cache);

	  return result;
	};


/***/ },
/* 5 */
/***/ function(module, exports) {

	module.exports = require("lru-cache");

/***/ },
/* 6 */
/***/ function(module, exports) {

	module.exports = require("lodash");

/***/ },
/* 7 */
/***/ function(module, exports) {

	module.exports = require("moment");

/***/ },
/* 8 */
/***/ function(module, exports) {

	module.exports = require("request");

/***/ },
/* 9 */
/***/ function(module, exports) {

	module.exports = require("useragent");

/***/ },
/* 10 */
/***/ function(module, exports, __webpack_require__) {

	exports.auth0 = __webpack_require__(11);
	exports.fromConnect = exports.fromExpress = fromConnect;
	exports.fromHapi = fromHapi;
	exports.fromServer = exports.fromRestify = fromServer;

	// API functions

	function addAuth0(func) {
	    func.auth0 = function (options) {
	        return exports.auth0(func, options);
	    }

	    return func;
	}

	function fromConnect (connectFn) {
	    return addAuth0(function (context, req, res) {
	        var normalizeRouteRx = createRouteNormalizationRx(req.x_wt.jtn);

	        req.originalUrl = req.url;
	        req.url = req.url.replace(normalizeRouteRx, '/');
	        req.webtaskContext = attachStorageHelpers(context);

	        return connectFn(req, res);
	    });
	}

	function fromHapi(server) {
	    var webtaskContext;

	    server.ext('onRequest', function (request, response) {
	        var normalizeRouteRx = createRouteNormalizationRx(request.x_wt.jtn);

	        request.setUrl(request.url.replace(normalizeRouteRx, '/'));
	        request.webtaskContext = webtaskContext;
	    });

	    return addAuth0(function (context, req, res) {
	        var dispatchFn = server._dispatch();

	        webtaskContext = attachStorageHelpers(context);

	        dispatchFn(req, res);
	    });
	}

	function fromServer(httpServer) {
	    return addAuth0(function (context, req, res) {
	        var normalizeRouteRx = createRouteNormalizationRx(req.x_wt.jtn);

	        req.originalUrl = req.url;
	        req.url = req.url.replace(normalizeRouteRx, '/');
	        req.webtaskContext = attachStorageHelpers(context);

	        return httpServer.emit('request', req, res);
	    });
	}


	// Helper functions

	function createRouteNormalizationRx(jtn) {
	    var normalizeRouteBase = '^\/api\/run\/[^\/]+\/';
	    var normalizeNamedRoute = '(?:[^\/\?#]*\/?)?';

	    return new RegExp(
	        normalizeRouteBase + (
	        jtn
	            ?   normalizeNamedRoute
	            :   ''
	    ));
	}

	function attachStorageHelpers(context) {
	    context.read = context.secrets.EXT_STORAGE_URL
	        ?   readFromPath
	        :   readNotAvailable;
	    context.write = context.secrets.EXT_STORAGE_URL
	        ?   writeToPath
	        :   writeNotAvailable;

	    return context;


	    function readNotAvailable(path, options, cb) {
	        var Boom = __webpack_require__(19);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        cb(Boom.preconditionFailed('Storage is not available in this context'));
	    }

	    function readFromPath(path, options, cb) {
	        var Boom = __webpack_require__(19);
	        var Request = __webpack_require__(8);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        Request({
	            uri: context.secrets.EXT_STORAGE_URL,
	            method: 'GET',
	            headers: options.headers || {},
	            qs: { path: path },
	            json: true,
	        }, function (err, res, body) {
	            if (err) return cb(Boom.wrap(err, 502));
	            if (res.statusCode === 404 && Object.hasOwnProperty.call(options, 'defaultValue')) return cb(null, options.defaultValue);
	            if (res.statusCode >= 400) return cb(Boom.create(res.statusCode, body && body.message));

	            cb(null, body);
	        });
	    }

	    function writeNotAvailable(path, data, options, cb) {
	        var Boom = __webpack_require__(19);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        cb(Boom.preconditionFailed('Storage is not available in this context'));
	    }

	    function writeToPath(path, data, options, cb) {
	        var Boom = __webpack_require__(19);
	        var Request = __webpack_require__(8);

	        if (typeof options === 'function') {
	            cb = options;
	            options = {};
	        }

	        Request({
	            uri: context.secrets.EXT_STORAGE_URL,
	            method: 'PUT',
	            headers: options.headers || {},
	            qs: { path: path },
	            body: data,
	        }, function (err, res, body) {
	            if (err) return cb(Boom.wrap(err, 502));
	            if (res.statusCode >= 400) return cb(Boom.create(res.statusCode, body && body.message));

	            cb(null);
	        });
	    }
	}


/***/ },
/* 11 */
/***/ function(module, exports, __webpack_require__) {

	var url = __webpack_require__(12);
	var error = __webpack_require__(13);
	var handleAppEndpoint = __webpack_require__(14);
	var handleLogin = __webpack_require__(16);
	var handleCallback = __webpack_require__(17);

	module.exports = function (webtask, options) {
	    if (typeof webtask !== 'function' || webtask.length !== 3) {
	        throw new Error('The auth0() function can only be called on webtask functions with the (ctx, req, res) signature.');
	    }
	    if (!options) {
	        options = {};
	    }
	    if (typeof options !== 'object') {
	        throw new Error('The options parameter must be an object.');
	    }
	    if (options.scope && typeof options.scope !== 'string') {
	        throw new Error('The scope option, if specified, must be a string.');
	    }
	    if (options.authorized && ['string','function'].indexOf(typeof options.authorized) < 0 && !Array.isArray(options.authorized)) {
	        throw new Error('The authorized option, if specified, must be a string or array of strings with e-mail or domain names, or a function that accepts (ctx, req) and returns boolean.');
	    }
	    if (options.exclude && ['string','function'].indexOf(typeof options.exclude) < 0 && !Array.isArray(options.exclude)) {
	        throw new Error('The exclude option, if specified, must be a string or array of strings with URL paths that do not require authentication, or a function that accepts (ctx, req, appPath) and returns boolean.');
	    }
	    if (options.clientId && typeof options.clientId !== 'function') {
	        throw new Error('The clientId option, if specified, must be a function that accepts (ctx, req) and returns an Auth0 Client ID.');
	    }
	    if (options.clientSecret && typeof options.clientSecret !== 'function') {
	        throw new Error('The clientSecret option, if specified, must be a function that accepts (ctx, req) and returns an Auth0 Client Secret.');
	    }
	    if (options.domain && typeof options.domain !== 'function') {
	        throw new Error('The domain option, if specified, must be a function that accepts (ctx, req) and returns an Auth0 Domain.');
	    }
	    if (options.webtaskSecret && typeof options.webtaskSecret !== 'function') {
	        throw new Error('The webtaskSecret option, if specified, must be a function that accepts (ctx, req) and returns a key to be used to sign issued JWT tokens.');
	    }
	    if (options.getApiKey && typeof options.getApiKey !== 'function') {
	        throw new Error('The getApiKey option, if specified, must be a function that accepts (ctx, req) and returns an apiKey associated with the request.');
	    }
	    if (options.loginSuccess && typeof options.loginSuccess !== 'function') {
	        throw new Error('The loginSuccess option, if specified, must be a function that accepts (ctx, req, res, baseUrl) and generates a response.');
	    }
	    if (options.loginError && typeof options.loginError !== 'function') {
	        throw new Error('The loginError option, if specified, must be a function that accepts (error, ctx, req, res, baseUrl) and generates a response.');
	    }

	    options.clientId = options.clientId || function (ctx, req) {
	        return ctx.secrets.AUTH0_CLIENT_ID;
	    };
	    options.clientSecret = options.clientSecret || function (ctx, req) {
	        return ctx.secrets.AUTH0_CLIENT_SECRET;
	    };
	    options.domain = options.domain || function (ctx, req) {
	        return ctx.secrets.AUTH0_DOMAIN;
	    };
	    options.webtaskSecret = options.webtaskSecret || function (ctx, req) {
	        // By default we don't expect developers to specify WEBTASK_SECRET when
	        // creating authenticated webtasks. In this case we will use webtask token
	        // itself as a JWT signing key. The webtask token of a named webtask is secret
	        // and it contains enough entropy (jti, iat, ca) to pass
	        // for a symmetric key. Using webtask token ensures that the JWT signing secret 
	        // remains constant for the lifetime of the webtask; however regenerating 
	        // the webtask will invalidate previously issued JWTs. 
	        return ctx.secrets.WEBTASK_SECRET || req.x_wt.token;
	    };
	    options.getApiKey = options.getApiKey || function (ctx, req) {
	        if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
	            return req.headers.authorization.split(' ')[1];
	        } else if (req.query && req.query.apiKey) {
	            return req.query.apiKey;
	        }
	        return null;
	    };
	    options.loginSuccess = options.loginSuccess || function (ctx, req, res, baseUrl) {
	        res.writeHead(302, { Location: baseUrl + '?apiKey=' + ctx.apiKey });
	        return res.end();
	    };
	    options.loginError = options.loginError || function (error, ctx, req, res, baseUrl) {
	        if (req.method === 'GET') {
	            if (error.redirect) {
	                res.writeHead(302, { Location: error.redirect });
	                return res.end(JSON.stringify(error));
	            }
	            res.writeHead(error.code || 401, { 
	                'Content-Type': 'text/html', 
	                'Cache-Control': 'no-cache' 
	            });
	            return res.end(getNotAuthorizedHtml(baseUrl + '/login'));
	        }
	        else {
	            // Reject all other requests
	            return error(error, res);
	        }            
	    };
	    if (typeof options.authorized === 'string') {
	        options.authorized = [ options.authorized ];
	    }
	    if (Array.isArray(options.authorized)) {
	        var authorized = [];
	        options.authorized.forEach(function (a) {
	            authorized.push(a.toLowerCase());
	        });
	        options.authorized = function (ctx, res) {
	            if (ctx.user.email_verified) {
	                for (var i = 0; i < authorized.length; i++) {
	                    var email = ctx.user.email.toLowerCase();
	                    if (email === authorized[i] || authorized[i][0] === '@' && email.indexOf(authorized[i]) > 1) {
	                        return true;
	                    }
	                }
	            }
	            return false;
	        }
	    }
	    if (typeof options.exclude === 'string') {
	        options.exclude = [ options.exclude ];
	    }
	    if (Array.isArray(options.exclude)) {
	        var exclude = options.exclude;
	        options.exclude = function (ctx, res, appPath) {
	            return exclude.indexOf(appPath) > -1;
	        }
	    }

	    return createAuthenticatedWebtask(webtask, options);
	};

	function createAuthenticatedWebtask(webtask, options) {

	    // Inject middleware into the HTTP pipeline before the webtask handler
	    // to implement authentication endpoints and perform authentication 
	    // and authorization.

	    return function (ctx, req, res) {
	        if (!req.x_wt.jtn || !req.x_wt.container) {
	            return error({
	                code: 400,
	                message: 'Auth0 authentication can only be used with named webtasks.'
	            }, res);
	        }

	        var routingInfo = getRoutingInfo(req);
	        if (!routingInfo) {
	            return error({
	                code: 400,
	                message: 'Error processing request URL path.'
	            }, res);
	        }
	        switch (req.method === 'GET' && routingInfo.appPath) {
	            case '/login': handleLogin(options, ctx, req, res, routingInfo); break;
	            case '/callback': handleCallback(options, ctx, req, res, routingInfo); break;
	            default: handleAppEndpoint(webtask, options, ctx, req, res, routingInfo); break;
	        };
	        return;
	    };
	}

	function getRoutingInfo(req) {
	    var routingInfo = url.parse(req.url, true);
	    var segments = routingInfo.pathname.split('/');
	    if (segments[1] === 'api' && segments[2] === 'run' && segments[3] === req.x_wt.container && segments[4] === req.x_wt.jtn) {
	        // Shared domain case: /api/run/{container}/{jtn}
	        routingInfo.basePath = segments.splice(0, 5).join('/');
	    }
	    else if (segments[1] === req.x_wt.container && segments[2] === req.x_wt.jtn) {
	        // Custom domain case: /{container}/{jtn}
	        routingInfo.basePath = segments.splice(0, 3).join('/');
	    }
	    else {
	        return null;
	    }
	    routingInfo.appPath = '/' + segments.join('/');
	    routingInfo.baseUrl = [
	        req.headers['x-forwarded-proto'] || 'https',
	        '://',
	        req.headers.host,
	        routingInfo.basePath
	    ].join('');
	    return routingInfo;
	}

	var notAuthorizedTemplate = function () {/*
	<!DOCTYPE html5>
	<html>
	  <head>
	    <meta charset="utf-8"/>
	    <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
	    <meta name="viewport" content="width=device-width, initial-scale=1"/>
	    <link href="https://cdn.auth0.com/styleguide/latest/index.css" rel="stylesheet" />
	    <title>Access denied</title>
	  </head>
	  <body>
	    <div class="container">
	      <div class="row text-center">
	        <h1><a href="https://auth0.com" title="Go to Auth0!"><img src="https://cdn.auth0.com/styleguide/1.0.0/img/badge.svg" alt="Auth0 badge" /></a></h1>
	        <h1>Not authorized</h1>
	        <p><a href="##">Try again</a></p>
	      </div>
	    </div>
	  </body>
	</html>
	*/}.toString().match(/[^]*\/\*([^]*)\*\/\s*\}$/)[1];

	function getNotAuthorizedHtml(loginUrl) {
	    return notAuthorizedTemplate.replace('##', loginUrl);
	}


/***/ },
/* 12 */
/***/ function(module, exports) {

	module.exports = require("url");

/***/ },
/* 13 */
/***/ function(module, exports) {

	module.exports = function (err, res) {
	    res.writeHead(err.code || 500, { 
	        'Content-Type': 'application/json',
	        'Cache-Control': 'no-cache'
	    });
	    res.end(JSON.stringify(err));
	};


/***/ },
/* 14 */
/***/ function(module, exports, __webpack_require__) {

	var error = __webpack_require__(13);

	module.exports = function (webtask, options, ctx, req, res, routingInfo) {
	    return options.exclude && options.exclude(ctx, req, routingInfo.appPath)
	        ? run()
	        : authenticate();

	    function authenticate() {
	        var apiKey = options.getApiKey(ctx, req);
	        if (!apiKey) {
	            return options.loginError({
	                code: 401,
	                message: 'Unauthorized.',
	                error: 'Missing apiKey.',
	                redirect: routingInfo.baseUrl + '/login'
	            }, ctx, req, res, routingInfo.baseUrl);
	        }

	        // Authenticate

	        var secret = options.webtaskSecret(ctx, req);
	        if (!secret) {
	            return error({
	                code: 400,
	                message: 'The webtask secret must be provided to allow for validating apiKeys.'
	            }, res);
	        }

	        try {
	            ctx.user = req.user = __webpack_require__(15).verify(apiKey, secret);
	        }
	        catch (e) {
	            return options.loginError({
	                code: 401,
	                message: 'Unauthorized.',
	                error: e.message
	            }, ctx, req, res, routingInfo.baseUrl);       
	        }

	        ctx.apiKey = apiKey;

	        // Authorize

	        if  (options.authorized && !options.authorized(ctx, req)) {
	            return options.loginError({
	                code: 403,
	                message: 'Forbidden.'
	            }, ctx, req, res, routingInfo.baseUrl);        
	        }

	        return run();
	    }

	    function run() {
	        // Route request to webtask code
	        return webtask(ctx, req, res);
	    }
	};


/***/ },
/* 15 */
/***/ function(module, exports) {

	module.exports = require("jsonwebtoken");

/***/ },
/* 16 */
/***/ function(module, exports, __webpack_require__) {

	var error = __webpack_require__(13);

	module.exports = function(options, ctx, req, res, routingInfo) {
	    var authParams = {
	        clientId: options.clientId(ctx, req),
	        domain: options.domain(ctx, req)
	    };
	    var count = !!authParams.clientId + !!authParams.domain;
	    var scope = 'openid name email email_verified ' + (options.scope || '');
	    if (count ===  0) {
	        // TODO, tjanczuk, support the shared Auth0 application case
	        return error({
	            code: 501,
	            message: 'Not implemented.'
	        }, res);
	        // Neither client id or domain are specified; use shared Auth0 settings
	        // var authUrl = 'https://auth0.auth0.com/i/oauth2/authorize'
	        //     + '?response_type=code'
	        //     + '&audience=https://auth0.auth0.com/userinfo'
	        //     + '&scope=' + encodeURIComponent(scope)
	        //     + '&client_id=' + encodeURIComponent(routingInfo.baseUrl)
	        //     + '&redirect_uri=' + encodeURIComponent(routingInfo.baseUrl + '/callback');
	        // res.writeHead(302, { Location: authUrl });
	        // return res.end();
	    }
	    else if (count === 2) {
	        // Use custom Auth0 account
	        var authUrl = 'https://' + authParams.domain + '/authorize' 
	            + '?response_type=code'
	            + '&scope=' + encodeURIComponent(scope)
	            + '&client_id=' + encodeURIComponent(authParams.clientId)
	            + '&redirect_uri=' + encodeURIComponent(routingInfo.baseUrl + '/callback');
	        res.writeHead(302, { Location: authUrl });
	        return res.end();
	    }
	    else {
	        return error({
	            code: 400,
	            message: 'Both or neither Auth0 Client ID and Auth0 domain must be specified.'
	        }, res);
	    }
	};


/***/ },
/* 17 */
/***/ function(module, exports, __webpack_require__) {

	var error = __webpack_require__(13);

	module.exports = function (options, ctx, req, res, routingInfo) {
	    if (!ctx.query.code) {
	        return options.loginError({
	            code: 401,
	            message: 'Authentication error.',
	            callbackQuery: ctx.query
	        }, ctx, req, res, routingInfo.baseUrl);
	    }

	    var authParams = {
	        clientId: options.clientId(ctx, req),
	        domain: options.domain(ctx, req),
	        clientSecret: options.clientSecret(ctx, req)
	    };
	    var count = !!authParams.clientId + !!authParams.domain + !!authParams.clientSecret;
	    if (count !== 3) {
	        return error({
	            code: 400,
	            message: 'Auth0 Client ID, Client Secret, and Auth0 Domain must be specified.'
	        }, res);
	    }

	    return __webpack_require__(18)
	        .post('https://' + authParams.domain + '/oauth/token')
	        .type('form')
	        .send({
	            client_id: authParams.clientId,
	            client_secret: authParams.clientSecret,
	            redirect_uri: routingInfo.baseUrl + '/callback',
	            code: ctx.query.code,
	            grant_type: 'authorization_code'
	        })
	        .timeout(15000)
	        .end(function (err, ares) {
	            if (err || !ares.ok) {
	                return options.loginError({
	                    code: 502,
	                    message: 'OAuth code exchange completed with error.',
	                    error: err && err.message,
	                    auth0Status: ares && ares.status,
	                    auth0Response: ares && (ares.body || ares.text)
	                }, ctx, req, res, routingInfo.baseUrl);
	            }

	            return issueApiKey(ares.body.id_token);
	        });

	    function issueApiKey(id_token) {
	        var jwt = __webpack_require__(15);
	        var claims;
	        try {
	            claims = jwt.decode(id_token);
	        }
	        catch (e) {
	            return options.loginError({
	                code: 502,
	                message: 'Cannot parse id_token returned from Auth0.',
	                id_token: id_token,
	                error: e.message
	            }, ctx, req, res, routingInfo.baseUrl);
	        }

	        // Issue apiKey by re-signing the id_token claims 
	        // with configured secret (webtask token by default).

	        var secret = options.webtaskSecret(ctx, req);
	        if (!secret) {
	            return error({
	                code: 400,
	                message: 'The webtask secret must be be provided to allow for issuing apiKeys.'
	            }, res);
	        }

	        claims.iss = routingInfo.baseUrl;
	        req.user = ctx.user = claims;
	        ctx.apiKey = jwt.sign(claims, secret);

	        // Perform post-login action (redirect to /?apiKey=... by default)
	        return options.loginSuccess(ctx, req, res, routingInfo.baseUrl);
	    }
	};


/***/ },
/* 18 */
/***/ function(module, exports) {

	module.exports = require("superagent");

/***/ },
/* 19 */
/***/ function(module, exports) {

	module.exports = require("boom");

/***/ }
/******/ ]);