Strict Crumb Issuer Plugin
==========================

This plugin allows more restrictive CSRF protection token ("crumbs") than the default shipping with Jenkins.

Options
-------

* Expire the crumb after a set number of hours.
* Require that the session must match.
* Require that the referer HTTP header must match where the crumb was created.
* Protect against BREACH attack.
* Require that the client IP must match.

Limitations
-----------

* Referer: Untested in reverse proxy situations
