# goval-dictionary

This is tool to build a local copy of the OVAL. The local copy is generated in sqlite format, and the tool has a server mode for easy querying.

## Install Requirements

goval-dictionary requires the following packages.

- SQLite3 or MySQL
- git
- gcc
- go v1.8 or later
    - https://golang.org/doc/install

----
# Install 

```bash
$ mkdir -p $GOPATH/src/github.com/kotakanbe
$ cd $GOPATH/src/github.com/kotakanbe
$ git https://github.com/kotakanbe/goval-dictionary.git
$ cd goval-dictionary
$ make install
```

# Usage

Fetch OVAL data from RedHat.  

```bash
$ for i in {5..7}; do goval-dictionary fetch-redhat $i; done
```

Select from DB where package name is golang.

```bash
$ goval-dictionary select RedHat 7 golang
[Apr 10 10:22:43]  INFO Opening DB (sqlite3).
CVE-2015-5739
    {3399 319 golang 0:1.6.3-1.el7_2.1}
    {3400 319 golang-bin 0:1.6.3-1.el7_2.1}
    {3401 319 golang-docs 0:1.6.3-1.el7_2.1}
    {3402 319 golang-misc 0:1.6.3-1.el7_2.1}
    {3403 319 golang-src 0:1.6.3-1.el7_2.1}
    {3404 319 golang-tests 0:1.6.3-1.el7_2.1}
CVE-2015-5740
    {3399 319 golang 0:1.6.3-1.el7_2.1}
    {3400 319 golang-bin 0:1.6.3-1.el7_2.1}
    {3401 319 golang-docs 0:1.6.3-1.el7_2.1}
    {3402 319 golang-misc 0:1.6.3-1.el7_2.1}
    {3403 319 golang-src 0:1.6.3-1.el7_2.1}
    {3404 319 golang-tests 0:1.6.3-1.el7_2.1}
CVE-2015-5741
    {3399 319 golang 0:1.6.3-1.el7_2.1}
    {3400 319 golang-bin 0:1.6.3-1.el7_2.1}
    {3401 319 golang-docs 0:1.6.3-1.el7_2.1}
    {3402 319 golang-misc 0:1.6.3-1.el7_2.1}
    {3403 319 golang-src 0:1.6.3-1.el7_2.1}
    {3404 319 golang-tests 0:1.6.3-1.el7_2.1}
CVE-2016-3959
    {3399 319 golang 0:1.6.3-1.el7_2.1}
    {3400 319 golang-bin 0:1.6.3-1.el7_2.1}
    {3401 319 golang-docs 0:1.6.3-1.el7_2.1}
    {3402 319 golang-misc 0:1.6.3-1.el7_2.1}
    {3403 319 golang-src 0:1.6.3-1.el7_2.1}
    {3404 319 golang-tests 0:1.6.3-1.el7_2.1}
CVE-2016-5386
    {3399 319 golang 0:1.6.3-1.el7_2.1}
    {3400 319 golang-bin 0:1.6.3-1.el7_2.1}
    {3401 319 golang-docs 0:1.6.3-1.el7_2.1}
    {3402 319 golang-misc 0:1.6.3-1.el7_2.1}
    {3403 319 golang-src 0:1.6.3-1.el7_2.1}
    {3404 319 golang-tests 0:1.6.3-1.el7_2.1}
------------------
[]models.Definition{
  models.Definition{
    ID:          0x13f,
    MetaID:      0x1,
    Title:       "RHSA-2016:1538: golang security, bug fix, and enhancement update (Moderate)",
    Description: "The golang packages provide the Go programming language compiler.\n\nThe following packages have been upgraded to a newer upstream version: golang (1.6.3). (BZ#1346331)\n\nSecurity Fix(es):\n\n* An input-validation flaw was discovered in the Go programming language built in CGI implementation, which set the environment variable \"HTTP_PROXY\" using the incoming \"Proxy\" HTTP-request header. The environment variable \"HTTP_PROXY\" is used by numerous web clients, including Go's net/http package, to specify a proxy server to use for HTTP and, in some cases, HTTPS requests. This meant that when a CGI-based web application ran, an attacker could specify a proxy server which the application then used for subsequent outgoing requests, allowing a man-in-the-middle attack. (CVE-2016-5386)\n\nRed Hat would like to thank Scott Geary (VendHQ) for reporting this issue.",
    Advisory:    models.Advisory{
      ID:           0x13f,
      DefinitionID: 0x13f,
      Severity:     "Moderate",
      Cves:         []models.Cve{
        models.Cve{
          ID:         0x54f,
          AdvisoryID: 0x13f,
          CveID:      "CVE-2015-5739",
          Cvss2:      "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P",
          Cvss3:      "",
          Cwe:        "CWE-444",
          Href:       "https://access.redhat.com/security/cve/CVE-2015-5739",
          Public:     "20150729",
        },
        models.Cve{
          ID:         0x550,
          AdvisoryID: 0x13f,
          CveID:      "CVE-2015-5740",
          Cvss2:      "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P",
          Cvss3:      "",
          Cwe:        "CWE-444",
          Href:       "https://access.redhat.com/security/cve/CVE-2015-5740",
          Public:     "20150729",
        },
        models.Cve{
          ID:         0x551,
          AdvisoryID: 0x13f,
          CveID:      "CVE-2015-5741",
          Cvss2:      "6.8/AV:N/AC:M/Au:N/C:P/I:P/A:P",
          Cvss3:      "",
          Cwe:        "CWE-444",
          Href:       "https://access.redhat.com/security/cve/CVE-2015-5741",
          Public:     "20150729",
        },
        models.Cve{
          ID:         0x552,
          AdvisoryID: 0x13f,
          CveID:      "CVE-2016-3959",
          Cvss2:      "4.3/AV:N/AC:M/Au:N/C:N/I:N/A:P",
          Cvss3:      "5.3/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
          Cwe:        "CWE-835",
          Href:       "https://access.redhat.com/security/cve/CVE-2016-3959",
          Public:     "20160405",
        },
        models.Cve{
          ID:         0x553,
          AdvisoryID: 0x13f,
          CveID:      "CVE-2016-5386",
          Cvss2:      "5.0/AV:N/AC:L/Au:N/C:N/I:P/A:N",
          Cvss3:      "5.0/CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N",
          Cwe:        "CWE-20",
          Href:       "https://access.redhat.com/security/cve/CVE-2016-5386",
          Public:     "20160718",
        },
      },
      Bugzillas: []models.Bugzilla{
        models.Bugzilla{
          ID:         0x93f,
          AdvisoryID: 0x13f,
          BugzillaID: "1346331",
          URL:        "https://bugzilla.redhat.com/1346331",
          Title:      "REBASE to golang 1.6",
        },
        models.Bugzilla{
          ID:         0x940,
          AdvisoryID: 0x13f,
          BugzillaID: "1353798",
          URL:        "https://bugzilla.redhat.com/1353798",
          Title:      "CVE-2016-5386 Go: sets environmental variable  based on user supplied Proxy request header",
        },
      },
      AffectedCPEList: []models.Cpe{
        models.Cpe{
          ID:         0x204,
          AdvisoryID: 0x13f,
          Cpe:        "cpe:/o:redhat:enterprise_linux:7",
        },
      },
    },
    AffectedPacks: []models.Package{
      models.Package{
        ID:           0xd47,
        DefinitionID: 0x13f,
        Name:         "golang",
        Version:      "0:1.6.3-1.el7_2.1",
      },
      models.Package{
        ID:           0xd48,
        DefinitionID: 0x13f,
        Name:         "golang-bin",
        Version:      "0:1.6.3-1.el7_2.1",
      },
      models.Package{
        ID:           0xd49,
        DefinitionID: 0x13f,
        Name:         "golang-docs",
        Version:      "0:1.6.3-1.el7_2.1",
      },
      models.Package{
        ID:           0xd4a,
        DefinitionID: 0x13f,
        Name:         "golang-misc",
        Version:      "0:1.6.3-1.el7_2.1",
      },
      models.Package{
        ID:           0xd4b,
        DefinitionID: 0x13f,
        Name:         "golang-src",
        Version:      "0:1.6.3-1.el7_2.1",
      },
      models.Package{
        ID:           0xd4c,
        DefinitionID: 0x13f,
        Name:         "golang-tests",
        Version:      "0:1.6.3-1.el7_2.1",
      },
    },
    References: []models.Reference{
      models.Reference{
        ID:           0x68d,
        DefinitionID: 0x13f,
        Source:       "RHSA",
        RefID:        "RHSA-2016:1538-01",
        RefURL:       "https://rhn.redhat.com/errata/RHSA-2016-1538.html",
      },
      models.Reference{
        ID:           0x68e,
        DefinitionID: 0x13f,
        Source:       "CVE",
        RefID:        "CVE-2015-5739",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2015-5739",
      },
      models.Reference{
        ID:           0x68f,
        DefinitionID: 0x13f,
        Source:       "CVE",
        RefID:        "CVE-2015-5740",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2015-5740",
      },
      models.Reference{
        ID:           0x690,
        DefinitionID: 0x13f,
        Source:       "CVE",
        RefID:        "CVE-2015-5741",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2015-5741",
      },
      models.Reference{
        ID:           0x691,
        DefinitionID: 0x13f,
        Source:       "CVE",
        RefID:        "CVE-2016-3959",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2016-3959",
      },
      models.Reference{
        ID:           0x692,
        DefinitionID: 0x13f,
        Source:       "CVE",
        RefID:        "CVE-2016-5386",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2016-5386",
      },
    },
  },
}

```

----

# Data Source

- [RedHat](https://www.redhat.com/security/data/oval/)


----

# Authors

kotakanbe ([@kotakanbe](https://twitter.com/kotakanbe)) created goval-dictionary and [these fine people](https://github.com/future-architect/goval-dictionary/graphs/contributors) have contributed.

----

# Change Log

Please see [CHANGELOG](https://github.com/kotakanbe/goval-dictionary/blob/master/CHANGELOG.md).

----

# Licence

Please see [LICENSE](https://github.com/kotakanbe/goval-dictionary/blob/master/LICENSE).

