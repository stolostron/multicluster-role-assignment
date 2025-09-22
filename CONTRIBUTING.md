## Table of Contents

- [Contributions](#contributions)
- [Certificate of Origin](#certificate-of-origin)
- [Contributing A Patch](#contributing-a-patch)
- [Issue and Pull Request Management](#issue-and-pull-request-management)
- [Pre-check before submitting a PR](#pre-check-before-submitting-a-pr)
- [Build images](#build-images)

# Contributing guidelines

## Contributions

All contributions to the repository must be submitted under the terms of the [Apache Public License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

## Certificate of Origin

By contributing to this project you agree to the Developer Certificate of
Origin (DCO). This document was created by the Linux Kernel community and is a
simple statement that you, as a contributor, have the legal right to make the
contribution. See the [DCO](DCO) file for details.

## Contributing A Patch

1. Submit an issue describing your proposed change to the repo in question.
1. The [repo owners](OWNERS) will respond to your issue promptly.
1. Fork the desired repo, develop and test your code changes.
1. Submit a pull request.

## Issue and Pull Request Management

Anyone may comment on issues and submit reviews for pull requests. However, in
order to be assigned an issue or pull request, you must be a member of the
[stolostron](https://github.com/stolostron) GitHub organization.

Repo maintainers can assign you an issue or pull request by leaving a
`/assign <your Github ID>` comment on the issue or pull request.

## Pre-check before submitting a PR

When your code is ready to commit, please run following commands to check your code.
```bash
make build
```

### Testing your change
Make sure your `kubectl` context is set to your target cluster.
This will run the code locally:
#### Controller
Debug the code in an editor ie. VSCode, Cursor
```bash
{
    "version": "0.2.0",
  "configurations": [

    {
      "name": "Launch Package",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceRoot}/cmd/main.go",
      "args": [],
      "showLog": true
    }
  ]
}
```


You will see the log output on the Debug Console. Create a MulticlusterRoleAssignment resource on the hub cluster and you will see corresponding ClusterPermission resources created for each managed cluster that's referenced.

## Building the image
To build the image.
```bash
make docker-build
```
