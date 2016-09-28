const async = require('async');
const AWS = require('aws-sdk');
const express = require('express');
const memoizee = require('memoizee');
const moment = require('moment');
const Request = require('request');
const Webtask = require('webtask-tools');
const metadata = require('./webtask.json');

const app = express();

function lastLogCheckpoint(req, res) {
  const ctx = req.webtaskContext;
  const required_settings = [
    'AUTH0_DOMAIN',
    'AUTH0_CLIENT_ID',
    'AUTH0_CLIENT_SECRET',
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_BUCKET_NAME',
  ];
  const missing_settings = required_settings.filter((setting) => !ctx.data[setting]);
  const simultaneous_uploads = 5;

  if (missing_settings.length) {
    return res.status(400).send({ message: `Missing settings: ${missing_settings.join(', ')}` });
  }

  // If this is a scheduled task, we'll get the last log checkpoint from the previous run and continue from there.
  req.webtaskContext.storage.get((err, data) => {

    let startCheckpointId = typeof data === 'undefined' ? null : data.checkpointId;

    AWS.config.update({
      accessKeyId: ctx.data.AWS_ACCESS_KEY_ID,
      secretAccessKey: ctx.data.AWS_SECRET_ACCESS_KEY,
      region: ctx.data.AWS_REGION || 'us-west-2',
    });
    const s3 = new AWS.S3({apiVersion: '2006-03-01'});

    // Start the process.
    async.waterfall([
      (callback) => {
        const getLogs = (context) => {
          console.log(`Logs from: ${context.checkpointId || 'Start'}.`);

          let take = Number.parseInt(ctx.data.BATCH_SIZE, 10) || 100;

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
        console.log('Uploading logs to S3...');

        async.eachLimit(context.logs, simultaneous_uploads, (log, cb) => {
          const date = moment(log.date);
          const url = `${date.format('YYYY/MM/DD/HH')}/${date.toISOString()}-${log._id}.json`;
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

      return req.webtaskContext.storage.set({checkpointId: context.checkpointId, totalLogsProcessed: context.logs.length}, {force: 1}, (error) => {
        if (error) {
          console.log('Error storing checkpoint', error);
          return res.status(500).send({error: error});
        }

        console.log('Job complete.');
        res.sendStatus(200);
      });
    });

  });
}

function getLogsFromAuth0(domain, token, take, from, cb) {
  const url = `https://${domain}/api/v2/logs`;

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
    } else if (!(/^2/.test(`${res.statusCode}`))) {
      console.log('Error getting logs', res);
      cb(null, JSON.stringify(body));
    } else {
      cb(body);
    }
  });
}

const getTokenCached = memoizee(
  (apiUrl, audience, clientId, clientSecret, cb) => {
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
      } else if (!/^2/.test(`${res.statusCode}`)) {
        cb(null, JSON.stringify(body));
      } else {
        cb(body.access_token);
      }
    });
  },
  {
    normalizer: (args) => args[0],
    maxAge: 1000 * 60 * 60,
  },
);

app.use((req, res, next) => {
  const apiUrl = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/oauth/token`;
  const audience = `https://${req.webtaskContext.data.AUTH0_DOMAIN}/api/v2/`;
  const clientId = req.webtaskContext.data.AUTH0_CLIENT_ID;
  const clientSecret = req.webtaskContext.data.AUTH0_CLIENT_SECRET;

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

app.get('/meta', (req, res) => {
  res.status(200).send(metadata);
});

module.exports = Webtask.fromExpress(app);
