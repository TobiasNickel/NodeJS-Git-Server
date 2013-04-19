
###
	
	GOAL: A simple to setup and run, multi-tenant Git Server written in NodeJS.
	
	This was initially created to be used as a multi-tenant git server with powerful event triggers.
	
###



# Require the modules needed:
pushover 	= require 'pushover'
http		= require 'http'
async		= require 'async'




class GitServer
	
	
	
	
	###
		Constructor function for each instance of GitServer
		@param {Array} repos List of repositories
		@param {Array} users List of users with user/pass creds
		@param {String} repoLocation Location where the repo's are/will be stored
		@param {Int} port Port on which to run this server.
	###
	constructor: ( @repos = [], @users = [], @logging = false, @repoLocation = '/tmp/repos', @port = 7000 )->
		# Create the pushover git object:
		@git		= pushover @repoLocation, autoCreate:false
		@permMap	= fetch:'R', push:'W'
		# Setup the repo listeners:
		@gitListeners()
		# Go through all the @repo's and create them if they dont exist:
		@makeReposIfNull =>
			# Route requests to pushover:
			@server	= http.createServer @git.handle.bind(@git)
			# Open up the desired port ( 80 requires sudo )
			@server.listen @port, =>
				# Just let the console know we have started.
				console.log 'Server listening on ', @port
	
	
	
	# Log all arguments passed into this function IF @logging = true
	log: ()=>
		args = for key,value of arguments
			"#{value}"
		if @logging then console.log "LOG: ", args.join(' ')
	
	
	
	
	###
		Process the request and check for basic authentication.
		@param {Object} gitObject Git object from the pushover module
		@param {String} method Method we are getting security for ['fetch','push']
		@param {Object} repo Repo object that we are doing this method on
	###
	processSecurity: ( gitObject, method, repo )=>
		# Try to get the auth header
		req		= gitObject.request
		res		= gitObject.response
		auth 	= req.headers['authorization']
		if auth is undefined
			# if they didnt send a auth header, tell them we need one:
			res.statusCode = 401
			res.setHeader 'WWW-Authenticate', 'Basic realm="Secure Area"'
			res.end '<html><body>Need some creds son</body></html>'
		# now they should have responded with the auth headers:
		else
			# Decode the auth string
			plain_auth	= ( new Buffer( auth.split(' ')[1], 'base64' ) ).toString()
			# split the string to get username:password
			creds = plain_auth.split ':'
			# Send off this user info and authorize it:
			@permissableMethod creds[0], creds[1], method, repo, gitObject
	
	
	
	
	###
		Check to see if:  return
			Username and password match  return
			This user has permission to do this method on this repo
		
		@param {String} username Username of the requesting user
		@param {String} password Password of the requesting user
		@param {String} method Method we are checking against ['fetch','push']
		@param {Object} gitObject Git object from pushover module
	###
	permissableMethod: ( username, password, method, repo, gitObject )=>
		# Just let the console know someone is trying to do something that requires a password:
		@log username,'is trying to', method,'on repo:',repo.name,'...'
		# Find the user object:
		user = @getUser username, password, repo
		# check if the user exists:
		if user is false
			# This user isnt in this repo's .users array:
			@log username,'was rejected as this user doesnt exist'
			gitObject.reject 'Couldnt find this user'
		else
			if @permMap[ method ] in user.permissions
				@log username,'Successfully did a', method,'on',repo.name
				gitObject.accept()
			else
				@log username,'was rejected, no permission to',method,'on',repo.name
				gitObject.reject('Dont know of method: '+method)
	
	
	
	
	# Setup the listeners for git events:
	gitListeners: ()=>
		# On each git push request
		@git.on 'push', @onPush
		# On each git fetch request
		@git.on 'fetch', @onFetch
		# On each git info request
		@git.on 'info', @onFetch
	
	
	
	
	###
		Checks all the passed in repo's to make sure they all have a real .git directory.
		@params {Function} callback Function to call when we complete this task.
	###
	makeReposIfNull: ( callback )=>
		@log 'Making repos if they dont exist';
		# Get all the repo names in an Array
		repoNames = []
		for repo in @repos
			# Make sure this repo has the require fields, if so, add to array:
			if repo.name? and repo.anonRead? and repo.users?
				repoNames.push("#{repo.name}.git")
			# This repo was missing some field we require
			else
				console.log 'Bad Repo', repo.name, 'is missing an attribute..'
		# Call .exists on each repo name
		async.reject repoNames, @git.exists.bind(@git), ( results )=>
			# If we have repo's that need to be created:
			if results.length > 0
				# Create each repo that doesn not exist:
				console.log('Creating repo directory: ', repo ) for repo in results
				# call .create on each repo:
				async.map results, @git.create.bind(@git), callback
			else callback() # Otherwise, open up the server.
	
	
	
	
	###
		When the git fetch command is triggered, this is fired.
		@param {Object} fetch Git object from pushover module.
	###
	onFetch: ( fetch )=>
		@log 'Got a FETCH call for', fetch.repo
		repo = @getRepo fetch.repo
		if repo isnt false # if this repo actually exists:
			# This repo allows anyone to fetch it, so accept the request:
			if repo.anonRead is true
				fetch.accept()
			# this repo has no anon access, so we need to check the user/pass
			else
				@processSecurity fetch, 'fetch', repo
		else # otherwise we need to reject this
			@log 'Rejected - Repo',fetch.repo,'doesnt exist'
			fetch.reject('This repo doesnt exist')
	
	
	
	
	###
		When the git push command is triggered, this is fired.
		@param {Object} push Git object from pushover module.
	###
	onPush: ( push )=>
		@log 'Got a PUSH call for', push.repo
		repo = @getRepo push.repo
		if repo isnt false # if this repo actually exists:
			@processSecurity push, 'push', repo
		else
			@log 'Rejected - Repo',push.repo,'doesnt exist'
			push.reject('This repo doesnt exist')
	
	
	
	
	###
		Get the user object, check user/pass is correct and it exists in this repo.
		@param {String} username Username to find
		@param {String} password Password of the Username
		@param {Object} repo Repo object this user should be in.
	###
	getUser: ( username, password, repo )=>
		for userObject in repo.users
			# If we found this user, return it
			return userObject if userObject.user.username is username and userObject.user.password is password
		false # Otherwise, return a false
	
	
	
	
	###
		Get the repo from the array of repos
		@param {String} repoName Name of the repo we are trying to find
	###
	getRepo: ( repoName )=>
		for repo in @repos
			# If the repo exists, return it. 
			return repo if repo.name+'.git' is repoName
		false # Otherwise, return a false



# Export this as a module:
module.exports = GitServer

