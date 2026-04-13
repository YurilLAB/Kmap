# Table of Contents
---

 * [Introduction](#intro)
 * [Code Repository](#repo)
 * [Bug Reports](#bug)
 * [Pull Requests](#pr)
 * [issues.kmap.org redirector](#issues)
 * [The HACKING file](#hacking)

## <a name="intro"></a>Introduction

This file serves as a supplement to the [HACKING file](HACKING). It contains information specifically about Kmap's use of Github and how contributors can use Github services to participate in Kmap development.

## <a name="repo"></a>Code Repository

The authoritative code repository is still the Subversion repository at [https://svn.kmap.org/kmap](https://svn.kmap.org/kmap). The Github repository is synchronized once per hour. All commits are made directly to Subversion, so Github is a read-only mirror.

## <a name="bug"></a>Bug Reports

Kmap uses Github Issues to keep track of bug reports. Please be sure to include the version of Kmap that you are using, steps to reproduce the bug, and a description of what you expect to be the correct behavior.

## <a name="pr"></a>Pull Requests

Kmap welcomes your code contribution in the form of a Github Pull Request. Since the Github repository is currently read-only, we cannot merge directly from the PR. Instead, we will convert your PR into a patch and apply it to the Subversion repository. We will be sure to properly credit you in the CHANGELOG file, and the commit message will reference the PR number.

Because not all Kmap committers use Github daily, it is helpful to send a
notification email to [dev@kmap.org](mailto:dev@kmap.org) referencing the PR and including a short
description of the functionality of the patch.

Using pull requests has several advantages over emailed patches:

1. It allows Travis CI build tests to run and check for code issues.

2. Github's interface makes it easy to have a threaded discussion of code
changes.

3. Referencing contributions by PR number is more convenient than tracking by
[seclists.org](http://seclists.org/) mail archive URL, especially when the discussion spans more than
one quarter year.

## <a name="issues"></a>issues.kmap.org redirector

For convenience, you may use [issues.kmap.org](http://issues.kmap.org) to redirect to issues (bug reports and pull requests) by number (e.g. [http://issues.kmap.org/34](http://issues.kmap.org/34)) or to link to the new-issue page: [http://issues.kmap.org/new](http://issues.kmap.org/new).

## <a name="hacking"></a>The HACKING file

General information about hacking Kmap and engaging with our community of
developers and users can be found in the [HACKING file](HACKING). It describes how to get started, licensing, style guidance, and how to use the dev mailing list.
