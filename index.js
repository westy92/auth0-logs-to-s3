const async     = require('async');
const AWS       = require('aws-sdk');
const express   = require('express');
const memoizer  = require('lru-memoizer');
const moment    = require('moment');
const Request   = require('request');
const useragent = require('useragent');
const Webtask   = require('webtask-tools');

const app = express();

function lastLogCheckpoint(req, res) {
  let ctx = req.webtaskContext;
  let required_settings = [
    'AUTH0_DOMAIN',
    'AUTH0_CLIENT_ID',
    'AUTH0_CLIENT_SECRET',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_BUCKET_NAME',
  ];
  let missing_settings = required_settings.filter((setting) => !ctx.data[setting]);

  if (missing_settings.length) {
    return res.status(400).send({ message: `Missing settings: ${missing_settings.join(', ')}` });
  }

  // If this is a scheduled task, we'll get the last log checkpoint from the previous run and continue from there.
  req.webtaskContext.storage.get((err, data) => {

    let startCheckpointId = typeof data === 'undefined' ? null : data.checkpointId;

    AWS.config.update({
      accessKeyId: ctx.data.AWS_ACCESS_KEY_ID,
      secretAccessKey: ctx.data.AWS_SECRET_ACCESS_KEY,
      region: ctx.data.AWS_REGION,
    });
    const s3 = new AWS.S3({apiVersion: '2006-03-01'});

    // Start the process.
    async.waterfall([
      (callback) => {
        const params = {
          Bucket: ctx.data.AWS_BUCKET_NAME
        };
        s3.createBucket(params, (err) => callback(err));
      },
      (callback) => {
        const getLogs = (context) => {
          console.log(`Logs from: ${context.checkpointId || 'Start'}.`);

          let take = Number.parseInt(ctx.data.BATCH_SIZE);

          take = Math.min(100, take);

          context.logs = context.logs || [];

          getLogsFromAuth0(req.webtaskContext.data.AUTH0_DOMAIN, req.access_token, take, context.checkpointId, (logs, err) => {
            if (err) {
              console.log('Error getting logs from Auth0', err);
              return callback(err);
            }

            if (logs && logs.length) {
              logs.forEach((l) => context.logs.push(l));
              context.checkpointId = context.logs[context.logs.length - 1]._id;
            }

            console.log(`Total logs: ${context.logs.length}.`);
            return callback(null, context);
          });
        };

        getLogs({ checkpointId: startCheckpointId });
      },
      (context, callback) => {
        context.logs = context.logs.map((record) => {
          let level = 0;
          record.type_code = record.type;
          if (logTypes[record.type]) {
            level = logTypes[record.type].level;
            record.type = logTypes[record.type].event;
          }

          let agent = useragent.parse(record.user_agent);
          record.os = agent.os.toString();
          record.os_version = agent.os.toVersion();
          record.device = agent.device.toString();
          record.device_version = agent.device.toVersion();
          return record;
        });
        callback(null, context);
      },
      (context, callback) => {
        console.log('Uploading logs to S3...');

        async.eachLimit(context.logs, 5, (log, cb) => {
          const date = moment(log.date);
          const url = `${date.format('YYYY/MM/DD/HH')}/${log._id}.json`;
          console.log(`Uploading ${url}.`);

          const params = {
            Bucket: ctx.data.AWS_BUCKET_NAME,
            Key: url,
            Body: JSON.stringify(log),
            ContentType: 'application/json',
            ServerSideEncryption: 'AES256',
          };
          s3.putObject(params, (err) => cb(err));
        }, (err) => {
          if (err) {
            return callback(err);
          }

          console.log('Upload complete.');
          return callback(null, context);
        });
      }
    ], (err, context) => {
      if (err) {
        console.log('Job failed.', err);

        return req.webtaskContext.storage.set({checkpointId: startCheckpointId}, {force: 1}, (error) => {
          if (error) {
            console.log('Error storing startCheckpoint', error);
            return res.status(500).send({error: error});
          }

          res.status(500).send({
            error: err
          });
        });
      }

      console.log('Job complete.');
      return req.webtaskContext.storage.set({checkpointId: context.checkpointId, totalLogsProcessed: context.logs.length}, {force: 1}, (error) => {
        if (error) {
          console.log('Error storing checkpoint', error);
          return res.status(500).send({error: error});
        }

        res.sendStatus(200);
      });
    });

  });
}

const logTypes = {
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
  var url = `https://${domain}/api/v2/logs`;

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
      Authorization: `Bearer ${token}`,
      Accept: 'application/json'
    }
  }, (err, res, body) => {
    if (err) {
      console.log('Error getting logs', err);
      cb(null, err);
    } else if (!(/^2/.test('' + res.statusCode))) {
      console.log('Error getting logs', res);
      cb(null, JSON.stringify(body));
    } else {
      cb(body);
    }
  });
}

const getTokenCached = memoizer({
  load: (apiUrl, audience, clientId, clientSecret, cb) => {
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
    }, (err, res, body) => {
      if (err) {
        cb(null, err);
      } else if (!(/^2/.test('' + res.statusCode))) {
        cb(null, JSON.stringify(body));
      } else {
        cb(body.access_token);
      }
    });
  },
  hash: (apiUrl) => apiUrl,
  max: 100,
  maxAge: 1000 * 60 * 60
});

app.use((req, res, next) => {
  var apiUrl       = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/oauth/token`;
  var audience     = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/api/v2/`;
  var clientId     = req.webtaskContext.data.AUTH0_CLIENT_ID;
  var clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

  getTokenCached(apiUrl, audience, clientId, clientSecret, (access_token, err) => {
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
