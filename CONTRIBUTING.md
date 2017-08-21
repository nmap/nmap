# Table of Contents

 * [Contributions](#contributing)
 * [General ideas](#ideas)
 * [Code Repository](#repo)
 * [Bug Reports](#bug)
 * [issues.nmap.org redirector](#issues)

## <a name="contributing"></a>Contributions to Nmap

Nmap welcomes your code contribution in the form of a Github Pull Request. Since the Github repository is currently read-only, we cannot merge directly from the PR. Instead, we will convert your PR into a patch and apply it to the Subversion repository. We will be sure to properly credit you in the CHANGELOG file, and the commit message will reference the PR number.

Because not all Nmap committers use Github daily, it is helpful to send a
notification email to [dev@nmap.org](mailto:dev@nmap.org) referencing the PR and including a short
description of the functionality of the patch.

Using pull requests has several advantages over emailed patches:

1. It allows Travis CI build tests to run and check for code issues.

2. Github's interface makes it easy to have a threaded discussion of code
changes.

3. Referencing contributions by PR number is more convenient than tracking by
[seclists.org](http://seclists.org/) mail archive URL, especially when the discussion spans more than
one quarter year.

Code style guidelines and quality checking tools are documented at
https://secwiki.org/w/Nmap/Code_Standards . The short version is:

* Indent with 2 spaces, not tabs
* No trailing whitespace
* Be consistent
* Use comments

## <a name="ideas"></a>General Ideas

Of course, you are welcome to work on whatever suits your fancy.  But
some ideas of contributions that might be particularly useful are listed in
the todo file, available in todo/nmap.txt or online at
https://svn.nmap.org/nmap/todo/nmap.txt

o Bug reports and feature requests at http://issues.nmap.org/ are a good place
  to look for ideas.

o Script ideas page. Writing NSE scripts is an excellent way to contribute to
  the project. You can add your script ideas to our wiki page, or pick one and
  implement it. See: https://secwiki.org/w/Nmap_Script_Ideas

o Nmap GUI improvements -- Zenmap is the Nmap GUI. If you have
  enhancement ideas, give it a shot!  Alternatively, consider
  contributing to the NmapSI and Umit projects available at
  http://www.nmapsi4.org and http://umit.sourceforge.net respectively.
  There are also other satellite projects, with different level of activity,
  such as NmapGUI (http://sourceforge.net/projects/nmapgui) or Nmap::parser
  (http://rubynmap.sourceforge.net).

One of the best ways to help is to join the nmap-dev list
( https://nmap.org/mailman/listinfo/dev ).  Requests for
assistance and new Nmap-related projects are often posted there.

## <a name="repo"></a>Code Repository

The authoritative code repository is still the Subversion repository at [https://svn.nmap.org/nmap](https://svn.nmap.org/nmap). The Github repository is synchronized once per hour. All commits are made directly to Subversion, so Github is a read-only mirror.

## <a name="bug"></a>Bug Reports

Nmap uses Github Issues to keep track of bug reports. Please be sure to include the version of Nmap that you are using, steps to reproduce the bug, and a description of what you expect to be the correct behavior.

## <a name="issues"></a>issues.nmap.org redirector

For convenience, you may use [issues.nmap.org](http://issues.nmap.org) to redirect to issues (bug reports and pull requests) by number (e.g. [http://issues.nmap.org/34](http://issues.nmap.org/34)) or to link to the new-issue page: [http://issues.nmap.org/new](http://issues.nmap.org/new).
