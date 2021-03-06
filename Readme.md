## Auth-Passport Resource

This custom resource type allows you to authorize your users using the powerful [Passport](http://passportjs.org).
Currently, the following methods are supported for authentification:

* **local** (i.e. username + password) - ONLY HTTP-POST METHOD
* **Twitter** (using Api v1.1)
* **Twitter Token**
* **Facebook** (using OAuth)
* **Facebook-Token** (using OAuth)
* **GitHub**
* **GitHub Token**
* **Google**
* **Google Token**
* **Google Id-Token**
* **Dribbble**
* **Weibo**
* **Weibo Token**


Others can be implemented easily if Passport supports them.

### Requirements

* deployd (you'd have guessed that, probably :-))
* User-Collection named `users` with at least these custom fields:
```json
    {
        "socialAccount": {
            "name": "socialAccount",
            "type": "string",
            "typeLabel": "string",
            "required": false,
            "id": "socialAccount",
            "order": 0
        },
        "socialAccountId": {
            "name": "socialAccountId",
            "type": "string",
            "typeLabel": "string",
            "required": false,
            "id": "socialAccountId",
            "order": 1
        },
        "profile": {
            "name": "profile",
            "type": "object",
            "typeLabel": "object",
            "required": false,
            "id": "profile",
            "order": 2
        },
        "name": {
            "name": "name",
            "type": "string",
            "typeLabel": "string",
            "required": false,
            "id": "name",
            "order": 3
        }
    }
```
### Notice

In order to avoid the checks for username and password, dpd-passport creates a dummy username and a password hash. That makes it impossible to login locally, but are visible in the deployd backend and **must not be edited**!

#### Updating from v0.3.0 or lower

To avoid error for existing users after the update, every user has to login again before any updates of the user object can be achieved.

### Installation

In your app's root directory, type `npm install dpd-passport` into the command line or [download the source](https://bitbucket.org/simpletechs/dpd-passport). This should create a `dpd-passport` directory in your app's `node_modules` directory.

See [Installing Modules](http://docs.deployd.com/docs/using-modules/installing-modules.md) for details.

### Setup

Open your Dashboard and add the new Passport-Auth Resource. Then configure which modules you want to allow for your users and supply the required information for each module.

Note: You may supply the baseURL (your website's root) via the environment variable `DPD_PASSPORT_BASEURL`. This is especially useful when you have a single codebase for testing + production environments.

### Usage

Point your users to `/auth/{login,twitter,facebook,github,google,dribble,weibo}` to have them login (or signup) via the specified module.
After that, Auth-Passport completely takes over and redirects the users according to the OAuth(2) flow.

Also You can use `/auth/login` to login on local user collection but it has to be POST method.

### Usage in Mobile Apps

Auth-Passport was built with usage in mobile Apps in mind.

1.  From inside your mobile app, open a browser and point the user to your website's `/auth/{login,twitter,facebook,github,google,dribble,weibo}` endpoint. From there, Auth-Passport will take over and guide (i.e. redirect) your user through the different steps needed for each provider, until the user has authorized your app and logged in successfully.

    Now you can get hold of your user and his session, by specifying a `redirectURL` in the original request. After the login is done (no matter if it was successful or not), your user will be redirected to the specified URL.
    Supply some app-specific URL (see your platform's SDK on how that looks) and catch the response in your app.

2.  Alternatively, authenticate the user with the appropriate OAUTH SDK and send  a request with the received access token as follows:
    ````
    GET /auth/facebook/token?access_token=<TOKEN_HERE>
    ````
    or in the header like so:
    ````
    GET /auth/facebook/token HTTP/1.1
    Host: server.example.com
    Authorization: Bearer base64_access_token_string
    ````
    or
    ````
    GET /auth/facebook/token HTTP/1.1
    Host: server.example.com
    access_token: Bearer base64_access_token_string
    ````    

    Optionally, the access token can be transmitted via post:
    ````
    POST /auth/facebook/token HTTP/1.1
    Host: server.example.com

    access_token=base64_access_token_string
    ````

    **NOTE**: Facebook can easily be interchanged with any of Google, Github, Twitter and Weibo.

**Google Id-Token login**

The login using Googles Id-Token system is similar to OAuth, but the JSON body of requests needs to contain the property `id_token` with the corresponding token resolved using Googles Signin SDK.

**Response**

Auth-Passport will supply the following information:

* **sid** (String) Session ID in deployd, send this in every subsequent request
* **uid** (String) User ID of the user that just logged in
* **success** (Bool) `true`, if login was successfull
* **error** (String) contains the error message in case of an error

### Development

To get started with development, please fork this repository and make your desired changes. Please note that we do all our dev work on bitbucket, so while you may submit pull requests on github, we will only push releases to github once they are finished.

### Testing

This module is covered by tests that are run against the latest supported version of `deployd` (0.8.4 currently).

### Credits

We'd like to thank Passport for building this amazing auth-framework!

Auth-Passport is the work of [simpleTechs.net](https://www.simpletechs.net)

### Contributors

The following people contributed some of there valuable spare time to make this module even better. Please add yourself to the list, in case we forgot you.

* [Tristan](https://github.com/tmcnab)
* [Andy](https://github.com/hongkongkiwi)
* [Andrei](https://github.com/andreialecu)
* [Burak](https://github.com/burakcan)
* [Mathis](https://github.com/Maddis1337)
* [Dave](https://github.com/flavordaaave)
