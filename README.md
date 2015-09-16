# Introduction

This package adds a HTTP listener that can execute glue scripts. It is based on the [event-driven HTTP server](https://github.com/nablex/http-api) and does not support standard Servlet technology.
It includes a whole bunch of new methods specifically for HTTP as well and supports a wide array of annotations.

# Runtime Behavior

There are a number of runtime behaviors that can be influenced in order to differentiate between a production environment and a development environment:

- **refreshScripts**: if not specifically set, the glue listener will never refresh the repositories, so scripts are effectively cached. If set, the repositories are refreshed for each call allowing for easy development 
- **allowEncoding**: this setting (by default "true") will indicate that the glue listener should listen to encoding support from the client. If the client indicates that he supports gzip or deflate, these algorithms are automatically used on the returning content

In combination, these settings can easily make a 5-fold difference in response times so use them wisely.

# Utilities versus Pages

For security reasons not all scripts are automatically accessible from the browser, in fact by default none are. There are two ways to make a script available to the client:

- The repository it belongs to has the category "public". This can be managed by whoever uses the listener (e.g. check the glue web server)
- The script can explicitly contain the script-level annotation `@page`

Note that scripts are exposed (by default) using only their **full name** at the path where the listener is situated. If you are listening at the root of the HTTP server and you have a script called `users/list.glue`, it will be accessible at `http://example.com/users/list` (without extension by default). The only exception to this is REST-scripts (see below) where the path must still _start_ with the full name but can have more data that is then mapped to the defined parameters.

# User Data

You can insert user data from various sources:

```python
@get
myVar ?= null

@post fieldName
myOtherVar ?= null
```

If nothing is passed in with the annotation, the variable name is assumed to match the field name in the source. If this is not the case you can give the original field name after the annotation. You can inject data using:

- **@get**
- **@post**: for file submits, the name of the field will return the byte content. To get metadata about the file itself, you can use: 
	- @post myFile:fileName
	- @post myFile:contentType
- **@cookie**
- **@header**: some headers are preparsed (unless you disable preparsing), for example the "If-Modified-Since" header is a date object, not the original string. You can always access the original headers using the method `request.header()`
- **@session**
- **@path**: check REST support
- **@meta**: this injects metadata about the request, possible values are:
	- contentType
	- contentLength
	- charset
	- contentRange
	- name
	- method
	- target
	- url
- **@content**: if no typing is given for the variable, you will get the actual byte stream of the content. However if a type was set, the data will be unmarshalled if it was originally JSON or XML into the given object. Note that you can manually parse the data as well (if you have the respective glue-json or glue-xml plugin):

```python
@content
theBytes ?= null

content = json.objectify(theBytes)
```

Note that data is only injected right before the line is executed so data for lines that are not executed (due to conditional circumstances) is never injected.
These annotations have method equivalents if you want more control.

# Response Data

There are two ways to set the response data:

- **response.content()**: you can use this method to set the response content. This content can be a stream, bytes, string, object,... If an object, it will use (if allowed) the `Accept` header from the client to determine whether he would prefer the data as JSON or XML and provide it as such. This method will also set `Content-Type` (if possible) and `Content-Length` (again if possible) headers.
- **echo()**: anything you echo is basically sent back as response to the client **unless** response.content() is used.

# Permission Handling

Assuming you use the provided methods for authentication, you can do this:

```
@role guest
doSomething()

@role user
doSomethingElse()

@permission toDoStuff
sequence
	doTheStuff()
	notifyThatTheStuffIsDone()
```

The respective lines will only be executed if the user has the required roles/permissions. If multiple roles are provided, the user must have **one** of the listed roles, not **all**.

These annotations also have method equivalents. 

# REST Support

There is native rest support which you can use by setting an annotation at the script level:

```python
@path {id}/view

@path
id ?= null
``` 

If your script is called `users.glue` for example, the following URL would work on the server: `http://example.com/users/1234/view`. This behavior can be turned off in the listener.
The syntax for the variables follows that of the JAX-RS API, which means you can specify a regex to match: `{id: [0-9]+}/view` would make sure the id was numeric.

Using the `@content` annotation described above you can easily get the parsed data from the request. 

You can use the above described `response.content()` method to set an object as response.

# CSRF Support

Unless specifically disabled in the listener, it will automatically add a CSRF token to any outgoing form and check it on any incoming form.

# Available Methods

The methods are divided by their domain. Unlike most glue methods they do not rely on their uniqueness in naming which means the coding guideline is to use the full name always.

- Request methods
	- **request.content()**: get the full content (the actual HTTPRequest object)
	- **request.header(name)**: get the first header object for the given name
	- **request.headers(name)**: get all header objects for the given name
	- **request.method()**: returns the method of the requests
	- **request.target()**: returns the target of the request
	- **request.version()**: returns the version of the request
	- There are a few methods that are structured the same for different data sources:1
		- **request.cookies()**: get a full map of all the cookies
		- **request.cookies(name)**: get a list of all the values for a specific cookie
		- **request.cookie(name)**: get the value for a specific cookie (if there are multiple, the first)
		- **request.gets()**
		- **request.gets(name)**
		- **request.get(name)**
		- **request.posts()**
		- **request.posts(name)**
		- **request.post(name)**
		- **request.paths()**
		- **request.paths(name)**
		- **request.path(name)**
- Response methods
	- **response.header(key, value)**: Adds a header to the response with the given key and value. If you have comments, put them in the value as well.
	- **response.code(number)**: sets the response code
	- **response.content(content, contentType)**: set the given content and (optionally) the content type for it. If no content type is given, it will be a best effort guess.
	- **response.cookie(key, value, expires, path, domain, secure, httpOnly)**: set a cookie in the response. Note that as for any method, all parameters are optional and most have sensible defaults.
	- **response.charset(name)**: set a specific charset for the response
	- **response.redirect(location, isPermanent)**: redirect the user
	- **response.notModified()**: send back a response that nothing was modified
	- **response.cache(maxAge, revalidate, private)**: directly set the cache header
- Session methods
	- **session.get(key)**: get the value for the given key
	- **session.set(key, value)**: set the value for the given key
	- **session.destroy()**: destroys the current session
	- **session.exists()**: checks if there is a session
	- **session.create(shouldCopy)**: creates a new session. If the shouldCopy is set to true (default false), all values of the current session (if any) are copied into the new one
- User methods
	- **user.authenticate(name, password, shouldRemember)**: authenticate the user with the given name and password. The shouldRemember boolean (default true) indicates whether or not a secret should be used to remember the user outside of the session. The availability of the remember option is dependent on the authenticator that is used however as not all authenticators support secrets. **Important**: successful authentication is automatically followed by generation of a new session to prevent fixation.
	- **user.remember()**: tries to remember the user based on a shared secret. This is again dependent on the authenticator.
	- **user.isAuthenticated()**: checks if the user is authenticated
	- **user.hasRoles(roles)**: checks if the user has **all** of the roles listed
	- **user.hasPermission(context, action)**: checks if the user has the given permission
	- **user.salt()**: generates a new salt based on a type 4 UUID
- Server methods
	- **server.fail(message, code)**: a HTTP error is created for the given code (500 by default) with the given message
	- **server.abort()**: stop the script from running without failure. Any response set up to that point is returned.
	- There are some log methods at different levels that use slf4j in the background
		- **server.debug(message)**
		- **server.info(message)**
		- **server.warn(message)**
		- **server.error(message)**
	