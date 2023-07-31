# Krtatos extended

This repository contains Kratos extensions developed by Monta.

## No direct commits to this repo dev/staging/main brahches

We do development in different branches.
The list is here: https://www.notion.so/montaapp/kratos-customisations-e42febf836b44a7488eb57d1c9a2c71e

Branches with public PR to Ory are in forked kratos repo (https://github.com/monta-app/kratos.git).
But branches with our internal non-public changes are in service-kratos (this repo).

We keep all these branches. To be able to rebase each individually and then merge them all together when upgrading to newer commit from kratos master.

This is why no commits should be added directly to dev/staging/main. Otherwise, those changes will be lost on the next kratos upgrade.
