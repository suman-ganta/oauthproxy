This is Nginx compatible oauth proxy that acts as oauth client and performs authentication flows

Configuration
-------------
TODO - Need to move out OAuth client config into a config file.

Endpoints
---------
It exposes the following endpoints:
/p/login - This is entry point for authentication flows. 
/p/callback - Endpoint to handle OAuth resource server callbacks. This exchanges auth code with access token. Also routes back to original request
/p/auth - Used by nginx to check if given request is authenticated.

Start server
------------
Currently it supports mvn clean install exec:java.
TODO - Dockerfile, k8s descriptor