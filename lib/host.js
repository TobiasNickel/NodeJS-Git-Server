/**

   
  
  GOAL: A simple to setup and run, multi-tenant Git Server written in NodeJS.
  
  This was initially created to be used as a multi-tenant git server with powerful event triggers.
  */
   
var pushover = require('pushover');
var http = require('http');
var https = require('https');
var async = require('async');
var fs = require('fs');
var crypto = require('crypto');
var git_events = require('git-emit');
var path = require('path');
var EventEmitter = require('events').EventEmitter;
var proxy = require('event-proxy');

var GitServer = (function() {
    /**
     * Constructor function for each instance of GitServer
     * @param {Array} repos List of repositories
     * @param {String} repoLocation Location where the repo's are/will be stored
     * @param {Int} port Port on which to run this server.
     * @param {Object} certs Object of 'key' and 'cert' with the location of the certs (only used for HTTPS)
     **/
    function GitServer(repos, logging, repoLocation, port, certs) {
        var that = this;
        this.repos = repos != null ? repos : [];
        this.logging = logging != null ? logging : false;
        this.repoLocation = repoLocation != null ? repoLocation : '/tmp/repos';
        this.port = port != null ? port : 7000;
        this.certs = certs;
        this.git = pushover(this.repoLocation, {
            autoCreate: false
        });
        this.permMap = {
            fetch: 'R',
            push: 'W'
        };
        this.gitListeners();
        this.makeReposIfNull(function() {
            that.bindEvents(function() {
                var message, red, reset;
                if (that.certs != null) {
                    that.server = https.createServer(that.certs, that.git.handle.bind(that.git));
                } else {
                    red = '\033[31m';
                    reset = '\033[0m';
                    message = "WARNING: No SSL certs passed in. Running as HTTP and not HTTPS.\nBe careful, without HTTPS your user/pass will not be encrypted";
                    console.log(red + message + reset);
                    that.server = http.createServer(that.git.handle.bind(that.git));
                }
                return that.server.listen(that.port, function() {
                    return that.log('Server listening on ', that.port, '\r');
                });
            });
        });
    }

    GitServer.prototype.bindEvents = function(callback) {
        var self = this;
        for (var i in this.repos) {
            this.repos[i].path = path.normalize(this.repoLocation + "/" + this.repos[i].name + ".git");
            this.repos[i].git_events = git_events(this.repos[i].path);
            this.repos[i].last_commit = {};
            this.repos[i].event = function(repo, update) {
                emitters = EventEmitter.listenerCount(self, update.name);
                if (emitters < 1 && update.canAbort) {
                    update.accept();
                } else {
                    self.emit(update.name, update, repo);
                }
            }
            var map = {
                "post-applypatch": this.repos[i].event,
                "post-commit": this.repos[i].event,
                "post-checkout": this.repos[i].event,
                "post-merge": this.repos[i].event,
                "post-receive": this.repos[i].event,
                "post-update": this.repos[i].event,
                "post-rewrite": this.repos[i].event,
                "applypatch-msg": this.repos[i].event,
                "pre-applypatch": this.repos[i].event,
                "pre-commit": this.repos[i].event,
                "prepare-commit-msg": this.repos[i].event,
                "commit-msg": this.repos[i].event,
                "pre-rebase": this.repos[i].event,
                "pre-receive": this.repos[i].event,
                "update": this.repos[i].event,
                "pre-auto-gc": this.repos[i].event
            }
            proxy(process, map, this.repos[i].git_events, this.repos[i]);
        }
        callback();
    }

    /**
     * Create a repo on the fly
     * @param {Object} repoName Name of the repo we are creating.
     **/


    GitServer.prototype.createRepo = function(repo, callback) {
        if ((repo.name == null) || (repo.anonRead == null)) {
            this.log('Not enough details, need atleast .name and .anonRead');
            false;
        }
        if (!this.getRepo(repo.name)) {
            this.log('Creating repo', repo.name);
            this.repos.push(repo);
            return this.git.create(repo.name, callback);
        } else {
            return this.log('This repo already exists');
        }
    };

    GitServer.prototype.log = function() {
        var args, key, value;
        args = (function() {
            var _results;
            _results = [];
            for (key in arguments) {
                value = arguments[key];
                _results.push("" + value);
            }
            return _results;
        }).apply(this, arguments);
        if (this.logging) {
            return console.log("LOG: ", args.join(' '));
        }
    };

    /**
     * Process the request and check for basic authentication.
     * @param {Object} gitObject Git object from the pushover module
     * @param {String} method Method we are getting security for ['fetch','push']
     * @param {Object} repo Repo object that we are doing this method on
     **/
    GitServer.prototype.processSecurity = function(gitObject, method, repo) {
        var auth, creds, plain_auth, req, res;
        req = gitObject.request;
        res = gitObject.response;
        auth = req.headers['authorization'];
        if (auth === undefined) {
            res.statusCode = 401;
            res.setHeader('WWW-Authenticate', 'Basic realm="Secure Area"');
            return res.end('<html><body>Need some creds son</body></html>');
        } else {
            plain_auth = (new Buffer(auth.split(' ')[1], 'base64')).toString();
            creds = plain_auth.split(':');
            return this.permissableMethod(creds[0], creds[1], method, repo, gitObject);
        }
    };

    /**
     * Check to see if:  return
     *   Username and password match  return
     *   This user has permission to do this method on this repo
     * 
     * @param {String} username Username of the requesting user
     * @param {String} password Password of the requesting user
     * @param {String} method Method we are checking against ['fetch','push']
     * @param {Object} gitObject Git object from pushover module
     **/
    GitServer.prototype.permissableMethod = function(username, password, method, repo, gitObject) {
        var user, _ref;
        this.log(username, 'is trying to', method, 'on repo:', repo.name, '...');
        user = this.getUser(username, password, repo);
        if (user === false) {
            this.log(username, 'was rejected as this user doesnt exist, or password is wrong');
            return gitObject.reject(500, 'Wrong username or password');
        } else {
            if (user.permissions.indexOf(this.permMap[method]) >= 0) {
                this.log(username, 'Successfully did a', method, 'on', repo.name);
                this.checkTriggers(method, repo, gitObject);
                return gitObject.accept();
            } else {
                this.log(username, 'was rejected, no permission to', method, 'on', repo.name);
                return gitObject.reject(500, "You dont have these permissions");
            }
        }
    };

    GitServer.prototype.gitListeners = function() {
        this.git.on('push', this.onPush.bind(this));
        this.git.on('fetch', this.onFetch.bind(this));
        return this.git.on('info', this.onFetch.bind(this));
    };

    /**
     * Checks all the passed in repo's to make sure they all have a real .git directory.
     * @params {Function} callback Function to call when we complete this task.
     **/
    GitServer.prototype.makeReposIfNull = function(callback) {
        var repo;
        var repoNames;
        var that = this;
        this.log('Making repos if they dont exist');
        repoNames = [];
        var repos = this.repos;
        for (var i = 0; i < repos.length; i++) {
            repo = repos[i];
            if ((repo.name != null) && (repo.anonRead != null) && (repo.users != null)) {
                repoNames.push("" + repo.name + ".git");
            } else {
                console.log('Bad Repo', repo.name, 'is missing an attribute..');
            }
        }
        return async.reject(repoNames, this.git.exists.bind(this.git), function(results) {
            if (results.length > 0) {
                for (var j = 0 ; j < results.length; j++) {
                    repo = results[j];
                    console.log('Creating repo directory: ', repo);
                }
                return async.map(results, that.git.create.bind(that.git), callback);
            } else {
                return callback();
            }
        });
    };

    /**
     * When the git fetch command is triggered, this is fired.
     * @param {Object} fetch Git object from pushover module.
     **/
    GitServer.prototype.onFetch = function(fetch) {
        var repo;
        this.log('Got a FETCH call for', fetch.repo);
        repo = this.getRepo(fetch.repo);
        if (repo !== false) {
            if (repo.anonRead === true) {
                this.checkTriggers('fetch', repo);
                return fetch.accept();
            } else {
                return this.processSecurity(fetch, 'fetch', repo);
            }
        } else {
            this.log('Rejected - Repo', fetch.repo, 'doesnt exist');
            return fetch.reject(500, 'This repo doesnt exist');
        }
    };

    /**
     * When the git push command is triggered, this is fired.
     * @param {Object} push Git object from pushover module.
     **/
    GitServer.prototype.onPush = function(push) {
        var repo;
        this.log('Got a PUSH call for', push.repo);
        repo = this.getRepo(push.repo);
        var data = {
            status: push.status,
            repo: push.repo,
            service: push.service,
            cwd: push.cwd,
            last: push.last,
            commit: push.commit,
            evName: push.evName,
            branch: push.branch
        }
        repo.last_commit = data;
        if (repo !== false) {
            return this.processSecurity(push, 'push', repo);
        } else {
            this.log('Rejected - Repo', push.repo, 'doesnt exist');
            return push.reject(500, 'This repo doesnt exist');
        }
    };

    /**
     * Check if this repo has onSuccessful triggers
     * @param {String} method fetch|push
     * @param {Object} repo Repo object we are checking
     **/
    GitServer.prototype.checkTriggers = function(method, repo, gitObject) {
        var _base;
        if (repo.onSuccessful != null) {
            if (repo.onSuccessful[method] != null) {
                this.log('On successful triggered: ', method, 'on', repo.name);
                _base = repo.onSuccessful
                return typeof(base)[method] === "function" ? _base[method](repo, method, gitObject) : undefined;
            }
        }
    };

    /**
     * Get the user object, check user/pass is correct and it exists in this repo.
     * @param {String} username Username to find
     * @param {String} password Password of the Username
     * @param {Object} repo Repo object this user should be in.
     **/
    GitServer.prototype.getUser = function(username, password, repo) {
        var userObject, i, users;
        var crypted_password = crypto.createHash('sha1').update(password).digest('hex');
        var users = repo.users;
        for (i = 0; i < users.length; i++) {
            userObject = users[i];
            if (userObject.user.username === username && (userObject.user.password === password || userObject.user.password === crypted_password)) {
                return userObject;
            }
        }
        return false;
    };

    /**
     * Get the repo from the array of repos
     * @param {String} repoName Name of the repo we are trying to find
     **/
     GitServer.prototype.getRepo = function(repoName) {
        var repo, _i, _len, _ref;
        var repos = this.repos;
        for (_i = 0; _i < repos.length; _i++) {
            repo = repos[_i];
            if (repo.name + '.git' === repoName) {
                return repo;
            }
        }
        return false;
    };

    GitServer.prototype.__proto__ = EventEmitter.prototype;

    return GitServer;
})();

module.exports = GitServer;
