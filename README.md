# Strict Crumb Issuer plugin

[![Build Status](https://ci.jenkins.io/job/Plugins/job/strict-crumb-issuer-plugin/job/main/badge/icon)](https://ci.jenkins.io/job/Plugins/job/strict-crumb-issuer-plugin/job/main/)
[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/strict-crumb-issuer.svg)](https://plugins.jenkins.io/strict-crumb-issuer)
[![Jenkins Plugin Installs](https://img.shields.io/jenkins/plugin/i/strict-crumb-issuer.svg?color=blue)](https://plugins.jenkins.io/strict-crumb-issuer)
[![GitHub license](https://img.shields.io/github/license/jenkinsci/strict-crumb-issuer-plugin)](https://github.com/jenkinsci/strict-crumb-issuer-plugin/blob/main/LICENSE.md)

## Description

The Strict Crumb Issuer plugin is an extended version of the Default Crumb Issuer embedded in Jenkins core. 
It provides advanced options of configuration.

It's strongly recommended to use a Crumb Issuer (this one or the embedded one), 
otherwise your instance will not be protected against [CSRF attacks](https://owasp.org/www-community/attacks/csrf).

## Screenshots

![Base options](/docs/images/sci_base_options.png)  

![Advanced options](/docs/images/sci_advanced_options.png)

## Changelog

### Version 2.1.1 (2023-05-06)

- Update Jenkins core requirements and some minor cleanup

### Version 2.1.0 (2019-12-19)

- Add compatibility for JCasC ([JENKINS-60523](https://issues.jenkins-ci.org/browse/JENKINS-60523))

### Version 2.0.1 (2019-07-18)

- Add wiki page link

### Version 2.0.0 (2019-07-17)

- First release, as a companion of [Security Advisory for SECURITY-626](https://jenkins.io/security/advisory/2019-07-17/#SECURITY-626)

## License

Licensed under MIT, see [LICENSE](LICENSE.md)
