var OAuth2Strategy = require('passport-oauth2')
  , util = require('util');

/**
 * `Strategy` constructor.
 *
 * Parameters:
 *    clientID: The client ID provided when you registered your app.
 *    clientSecret: The client secret provided when you registered your app.
 *    action: This is either "signup" or "signin", by default it's "signin".
 *
 * @param options
 * @param verify
 * @constructor
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || "https://id.webmaker.org/login/oauth/authorize";
  options.tokenURL = options.tokenURL || "https://id.webmaker.org/login/oauth/access_token";

  OAuth2Strategy.call(this, options, verify);
  this.name = "webmaker";
}

util.inherits(Strategy, OAuth2Strategy);

/**
 * Provided extra id.webmaker.org specific parameters to be included in the authorization request.
 *
 * @param options
 */
Strategy.prototype.authorizationParams = function(options) {
    var params = {};
    if (options.action) { params['action'] = options.action; }
    return params;
};

/**
 * Retrieve a user profile from id.webmaker.org and format it for easy accessibility.
 *
 * @param accessToken
 * @param done
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var profileEndPoint = 'https://id.webmaker.org/user';

  this._oauth2.useAuthorizationHeaderforGET(true);
  this._oauth2.get(profileEndPoint, accessToken, function (err, body, res) {
    if (err) { return done(new InternalOAuthError('Failed to fetch user profile.', err)); }

      try {
        var json = JSON.parse(body);
        var profile = { provider: 'webmaker' };

        profile.id = json.id;
        profile.displayName = json.username;
        profile.emails = [{ value: json.email }];
        profile.photos = [{ value: json.avatar }];

        done(null, profile);
      } catch (error) {
        done(error);
      }
  });
};

// Expose `Constructor` method.
module.exports = Strategy;