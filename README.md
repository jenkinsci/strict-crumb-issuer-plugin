# Strict Crumb Issuer plugin
[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/strict-crumb-issuer.svg)](https://plugins.jenkins.io/strict-crumb-issuer)
[![Jenkins Plugin Installs](https://img.shields.io/jenkins/plugin/i/strict-crumb-issuer.svg?color=blue)](https://plugins.jenkins.io/strict-crumb-issuer)

## Description

The Strict Crumb Issuer plugin is an extended version of the Default Crumb Issuer embedded in Jenkins core. 
It provides advanced options of configuration.

It's strongly recommended to use a Crumb Issuer (this one or the embedded one), 
otherwise your instance will not be protected against [CSRF attacks](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29).

## Screenshots

![Base options](/docs/images/sci_base_options.png)  

![Advanced options](/docs/images/sci_advanced_options.png)

## Changelog

### Version 2.1.0 (2019-12-19)

- Add compatibility for JCasC ([JENKINS-60523](https://issues.jenkins-ci.org/browse/JENKINS-60523))

### Version 2.0.1 (2019-07-18)

- Add wiki page link

### Version 2.0.0 (2019-07-17)

- First release, as a companion of [Security Advisory for SECURITY-626](https://jenkins.io/security/advisory/2019-07-17/#SECURITY-626)

  
