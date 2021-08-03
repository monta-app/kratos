# Krtatos extended
This repository contains Kratos extensions developed by Monta.

## No commits to this repo

All development should be done in the public fork:
https://github.com/monta-app/kratos.git

Commits here are allowed only to the `devops` branch.

## List of all active branches

| Branch name                                     | Comment                                                                                                                              |
|-------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| devops                                          | All modifications needed to build and deploy extended Kratos                                                                         |
| merge                                           | Here we merge everything from other branches                                                                                         |
| develop                                         | This is the source of deployment to the development environment                                                                      |
| feature/sms-login                               | Extension to implement loging with sms codes                                                                                         |
| feature/oidc-api                                | Extension to enable social logins from mobile devices                                                                                |
| feature/oidc-api-access-token                   | Add `access_token` parameter to oidc API flow. Should be discarded after fixing mobile app Google and Microsoft logins.              |
| feat-search                                     | Enables identities search in the admin API https://github.com/ory/kratos/pull/1671                                                   |
| fix-migrations-aurora                           | Fix for installing Kratos on AWS Aurora DB                                                                                           |
| fix-core-558                                    | Temporary fix to password recovery problem                                                                                           |
| fix-default-identity-schema                     | https://github.com/ory/kratos/pull/2393                                                                                              |
| fix-verification-csrf                           | https://github.com/ory/kratos/pull/2455                                                                                              |
| fix-core-581                                    | Temporary fix to mobile app email verification problem                                                                               |
| feat-log-inactive-identity-id                   | https://github.com/ory/kratos/pull/2557                                                                                              |
| feature/pin-login                               | https://github.com/ory/kratos/pull/2668                                                                                              |
| fix-verification-api                            | https://github.com/ory/kratos/pull/2542                                                                                              |
| monta-app/kratos/upgrade-kratos/feature/webview | Changes merged into feature/oidc-api and saml-webview. Should be deleted when one of these branches is merged into ory/kratos/master |
| saml-webview                                    | https://github.com/ovh/kratos/pull/4                                                                                                 |
