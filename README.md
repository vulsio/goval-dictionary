# goval-dictionary

This is tool to build a local copy of the OVAL. The local copy is generated in sqlite format, and the tool has a server mode for easy querying.

## Installation

### Requirements

goval-dictionary requires the following packages.

- SQLite3, MySQL, PostgreSQL or Redis
- git
- gcc
- go v1.8 or later
    - https://golang.org/doc/install

### Install

```bash
$ mkdir -p $GOPATH/src/github.com/kotakanbe
$ cd $GOPATH/src/github.com/kotakanbe
$ git clone https://github.com/kotakanbe/goval-dictionary.git
$ cd goval-dictionary
$ make install
```

----

## Usage

```bash
$ goval-dictionary -h
Usage: goval-dictionary <flags> <subcommand> <subcommand args>

Subcommands:
        commands         list all command names
        flags            describe all known top-level flags
        help             describe subcommands and their syntax

Subcommands for fetch-alpine:
        fetch-alpine     Fetch Vulnerability dictionary from Alpine secdb

Subcommands for fetch-debian:
        fetch-debian     Fetch Vulnerability dictionary from Debian

Subcommands for fetch-oracle:
        fetch-oracle     Fetch Vulnerability dictionary from Oracle

Subcommands for fetch-redhat:
        fetch-redhat     Fetch Vulnerability dictionary from RedHat

Subcommands for fetch-suse:
        fetch-suse       Fetch Vulnerability dictionary from SUSE

Subcommands for fetch-ubuntu:
        fetch-ubuntu     Fetch Vulnerability dictionary from Ubuntu

Subcommands for select:
        select           Select from DB

Subcommands for server:
        server           Start OVAL dictionary HTTP server


Use "goval-dictionary flags" for a list of top-level flags
```

### Usage: Fetch OVAL data from RedHat

- [Redhat OVAL](https://www.redhat.com/security/data/oval/)

```bash
$ goval-dictionary fetch-redhat -h
fetch-redhat:
        fetch-redhat
                [-dbtype=sqlite3|mysql|postgres|redis]
                [-dbpath=$PWD/oval.sqlite3 or connection string]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
                [-quiet]
                [-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
    $ goval-dictionary fetch-redhat 5 6 7
        or
    $ for i in {5..7}; do goval-dictionary fetch-redhat $i; done

  -dbpath string
        /path/to/sqlite3 or SQL connection string (default "$PWD/oval.sqlite3")
  -dbtype string
        Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)
  -quiet
        quiet mode (no output)
  -log-dir string
        /path/to/log (default "/var/log/vuls")
```

- Import OVAL data from Internet

```bash
$ goval-dictionary fetch-redhat 5 6 7
```

### Usage: Fetch OVAL data from Debian

- [Debian OVAL](https://www.debian.org/security/oval/)

```bash
$ goval-dictionary fetch-debian -h
fetch-debian:
        fetch-debian
                [-dbtype=sqlite3|mysql|postgres|redis]
                [-dbpath=$PWD/oval.sqlite3 or connection string]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
                [-quiet]
                [-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
    $ goval-dictionary fetch-debian 7 8 9 10

  -dbpath string
        /path/to/sqlite3 or SQL connection string (default "$PWD/oval.sqlite3")
  -dbtype string
        Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)
  -quiet
        quiet mode (no output)
  -log-dir string
        /path/to/log (default "/var/log/vuls")
```

- Import OVAL data from Internet

```bash
$ goval-dictionary fetch-debian 7 8 9 10
```

### Usage: Fetch OVAL data from Ubuntu

- [Ubuntu](https://people.canonical.com/~ubuntu-security/oval/)

```bash
$ goval-dictionary fetch-ubuntu -h
fetch-ubuntu:
        fetch-ubuntu
                [-dbtype=sqlite3|mysql|postgres|redis]
                [-dbpath=$PWD/oval.sqlite3 or connection string]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
                [-quiet]
                [-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
    $ goval-dictionary fetch-ubuntu 12 14 16

  -dbpath string
        /path/to/sqlite3 or SQL connection string (default "$PWD/oval.sqlite3")
  -dbtype string
        Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)
  -quiet
        quiet mode (no output)
  -log-dir string
        /path/to/log (default "/var/log/vuls")
```

- Import OVAL data from Internet

```bash
$ goval-dictionary fetch-ubuntu 12 14 16
```

### Usage: Fetch OVAL data from SUSE

- [SUSE](http://ftp.suse.com/pub/projects/security/oval/)

```bash
$ goval-dictionary fetch-suse -h
fetch-suse:
        fetch-suse
                [-opensuse]
                [-opensuse-leap]
                [-suse-enterprise-server]
                [-suse-enterprise-desktop]
                [-suse-openstack-cloud]
                [-dbtype=sqlite3|mysql|postgres|redis]
                [-dbpath=$PWD/oval.sqlite3 or connection string]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
                [-quiet]
                [-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
    $ goval-dictionary fetch-suse -opensuse 13.2

  -dbpath string
        /path/to/sqlite3 or SQL connection string (default "$PWD/oval.sqlite3")
  -dbtype string
        Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)
  -quiet
        quiet mode (no output)
  -log-dir string
        /path/to/log (default "/var/log/vuls")
  -opensuse
        OpenSUSE
  -opensuse-leap
        OpenSUSE Leap
  -suse-enterprise-server
        SUSE Enterprise Server
```

- Import OVAL data from Internet

```bash
$ goval-dictionary fetch-suse -opensuse 13.2
```

```bash
$ goval-dictionary fetch-suse -suse-enterprise-server 12

```

### Usage: Fetch OVAL data from Oracle

- [Oracle Linux](https://linux.oracle.com/security/oval/)

```bash
$ goval-dictionary fetch-oracle -h
fetch-oracle:
        fetch-oracle
                [-dbtype=sqlite3|mysql|postgres|redis]
                [-dbpath=$PWD/oval.sqlite3 or connection string]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
                [-quiet]
                [-log-dir=/path/to/log]

For the first time, run the blow command to fetch data for all versions.
    $ goval-dictionary fetch-oracle

  -dbpath string
        /path/to/sqlite3 or SQL connection string (default "$PWD/oval.sqlite3")
  -dbtype string
        Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)
  -quiet
        quiet mode (no output)
  -log-dir string
        /path/to/log (default "/var/log/vuls")
```

- Import OVAL data from Internet

```bash
 $ goval-dictionary fetch-oracle
```

### Usage: Fetch alpine-secdb as OVAL data type

- [Alpine Linux](https://git.alpinelinux.org/cgit/alpine-secdb/)
alpine-secdb is provided in YAML format and not OVAL, but it is supported by goval-dictionary to make alpine-secdb easier to handle from Vuls.
See [here](https://git.alpinelinux.org/cgit/alpine-secdb/tree/) for a list of supported alpines.

```bash
fetch-alpine:
        fetch-alpine
                [-dbtype=sqlite3|mysql|postgres|redis]
                [-dbpath=$PWD/oval.sqlite3 or connection string]
                [-http-proxy=http://192.168.0.1:8080]
                [-debug]
                [-debug-sql]
                [-quiet]
                [-log-dir=/path/to/log]

The version list is here https://git.alpinelinux.org/cgit/alpine-secdb/tree/
        $ goval-dictionary fetch-alpine 3.3 3.4 3.5 3.6

  -dbpath string
        /path/to/sqlite3 or SQL connection string (default "$PWD/oval.sqlite3")
  -dbtype string
        Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
  -debug
        debug mode
  -debug-sql
        SQL debug mode
  -http-proxy string
        http://proxy-url:port (default: empty)
  -log-dir string
        /path/to/log (default "/var/log/vuls")
  -quiet
        quiet mode (no output)
```

- Import alpine-secdb from Internet

```bash
 $ goval-dictionary fetch-alpine 3.3 3.4 3.5 3.6
```
See [here](https://git.alpinelinux.org/cgit/alpine-secdb/tree/) for a list of supported alpines.

### Usage: select oval by package name

Select from DB where package name is golang.

<details>
<summary> 
`$ goval-dictionary select -by-package RedHat 7 golang`
</summary>

```bash
$ goval-dictionary select -by-package RedHat 7 golang
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

</details>

### Usage: select oval by CVE-ID

<details>
<summary>
`Select from DB where CVE-ID CVE-2017-6009`
</summary>

```bash
$ goval-dictionary select -by-cveid RedHat 7 CVE-2017-6009
[Apr 12 12:12:36]  INFO Opening DB (sqlite3).
RHSA-2017:0837: icoutils security update (Important)
Important
[{1822 430 CVE-2017-5208  8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L CWE-190 CWE-122 https://access.redhat.com/security/cve/CVE-2017-5208 20170108} {1823 430 CVE-2017-5332  2.8/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L CWE-190 CWE-125 https://access.redhat.com/security/cve/CVE-2017-5332 20170108} {1824 430 CVE-2017-5333  8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L CWE-190 CWE-122 https://access.redhat.com/security/cve/CVE-2017-5333 20170108} {1825 430 CVE-2017-6009  8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L CWE-190 CWE-122 https://access.redhat.com/security/cve/CVE-2017-6009 20170203} {1826 430 CVE-2017-6010  8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L CWE-190 CWE-122 https://access.redhat.com/security/cve/CVE-2017-6010 20170203} {1827 430 CVE-2017-6011  8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L CWE-122 https://access.redhat.com/security/cve/CVE-2017-6011 20170203}]
------------------
[]models.Definition{
  models.Definition{
    ID:          0x1ae,
    MetaID:      0x1,
    Title:       "RHSA-2017:0837: icoutils security update (Important)",
    Description: "The icoutils are a set of programs for extracting and converting images in Microsoft Windows icon and cursor files. These files usually have the extension .ico or .cur, but they can also be embedded in executables or libraries.\n\nSecurity Fix(es):\n\n* Multiple vulnerabilities were found in icoutils, in the wrestool program. An attacker could create a crafted executable that, when read by wrestool, could result in memory corruption leading to a crash or potential code execution. (CVE-2017-5208, CVE-2017-5333, CVE-2017-6009)\n\n* A vulnerability was found in icoutils, in the wrestool program. An attacker could create a crafted executable that, when read by wrestool, could result in failure to allocate memory or an over-large memcpy operation, leading to a crash. (CVE-2017-5332)\n\n* Multiple vulnerabilities were found in icoutils, in the icotool program. An attacker could create a crafted ICO or CUR file that, when read by icotool, could result in memory corruption leading to a crash or potential code execution. (CVE-2017-6010, CVE-2017-6011)",
    Advisory:    models.Advisory{
      ID:           0x1ae,
      DefinitionID: 0x1ae,
      Severity:     "Important",
      Cves:         []models.Cve{
        models.Cve{
          ID:         0x71e,
          AdvisoryID: 0x1ae,
          CveID:      "CVE-2017-5208",
          Cvss2:      "",
          Cvss3:      "8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L",
          Cwe:        "CWE-190 CWE-122",
          Href:       "https://access.redhat.com/security/cve/CVE-2017-5208",
          Public:     "20170108",
        },
        models.Cve{
          ID:         0x71f,
          AdvisoryID: 0x1ae,
          CveID:      "CVE-2017-5332",
          Cvss2:      "",
          Cvss3:      "2.8/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L",
          Cwe:        "CWE-190 CWE-125",
          Href:       "https://access.redhat.com/security/cve/CVE-2017-5332",
          Public:     "20170108",
        },
        models.Cve{
          ID:         0x720,
          AdvisoryID: 0x1ae,
          CveID:      "CVE-2017-5333",
          Cvss2:      "",
          Cvss3:      "8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L",
          Cwe:        "CWE-190 CWE-122",
          Href:       "https://access.redhat.com/security/cve/CVE-2017-5333",
          Public:     "20170108",
        },
        models.Cve{
          ID:         0x721,
          AdvisoryID: 0x1ae,
          CveID:      "CVE-2017-6009",
          Cvss2:      "",
          Cvss3:      "8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L",
          Cwe:        "CWE-190 CWE-122",
          Href:       "https://access.redhat.com/security/cve/CVE-2017-6009",
          Public:     "20170203",
        },
        models.Cve{
          ID:         0x722,
          AdvisoryID: 0x1ae,
          CveID:      "CVE-2017-6010",
          Cvss2:      "",
          Cvss3:      "8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L",
          Cwe:        "CWE-190 CWE-122",
          Href:       "https://access.redhat.com/security/cve/CVE-2017-6010",
          Public:     "20170203",
        },
        models.Cve{
          ID:         0x723,
          AdvisoryID: 0x1ae,
          CveID:      "CVE-2017-6011",
          Cvss2:      "",
          Cvss3:      "8.1/CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L",
          Cwe:        "CWE-122",
          Href:       "https://access.redhat.com/security/cve/CVE-2017-6011",
          Public:     "20170203",
        },
      },
      Bugzillas: []models.Bugzilla{
        models.Bugzilla{
          ID:         0xe4a,
          AdvisoryID: 0x1ae,
          BugzillaID: "1411251",
          URL:        "https://bugzilla.redhat.com/1411251",
          Title:      "CVE-2017-5208 icoutils: Check_offset overflow on 64-bit systems",
        },
        models.Bugzilla{
          ID:         0xe4b,
          AdvisoryID: 0x1ae,
          BugzillaID: "1412259",
          URL:        "https://bugzilla.redhat.com/1412259",
          Title:      "CVE-2017-5333 icoutils: Integer overflow vulnerability in extract.c",
        },
        models.Bugzilla{
          ID:         0xe4c,
          AdvisoryID: 0x1ae,
          BugzillaID: "1412263",
          URL:        "https://bugzilla.redhat.com/1412263",
          Title:      "CVE-2017-5332 icoutils: Access to unallocated memory possible in extract.c",
        },
        models.Bugzilla{
          ID:         0xe4d,
          AdvisoryID: 0x1ae,
          BugzillaID: "1422906",
          URL:        "https://bugzilla.redhat.com/1422906",
          Title:      "CVE-2017-6009 icoutils: Buffer overflow in the decode_ne_resource_id function",
        },
        models.Bugzilla{
          ID:         0xe4e,
          AdvisoryID: 0x1ae,
          BugzillaID: "1422907",
          URL:        "https://bugzilla.redhat.com/1422907",
          Title:      "CVE-2017-6010 icoutils: Buffer overflow in the extract_icons function",
        },
        models.Bugzilla{
          ID:         0xe4f,
          AdvisoryID: 0x1ae,
          BugzillaID: "1422908",
          URL:        "https://bugzilla.redhat.com/1422908",
          Title:      "CVE-2017-6011 icoutils: Buffer overflow in the simple_vec function",
        },
      },
      AffectedCPEList: []models.Cpe{
        models.Cpe{
          ID:         0x2ae,
          AdvisoryID: 0x1ae,
          Cpe:        "cpe:/o:redhat:enterprise_linux:7",
        },
      },
    },
    AffectedPacks: []models.Package{
      models.Package{
        ID:           0x11b1,
        DefinitionID: 0x1ae,
        Name:         "icoutils",
        Version:      "0:0.31.3-1.el7_3",
      },
    },
    References: []models.Reference{
      models.Reference{
        ID:           0x8cb,
        DefinitionID: 0x1ae,
        Source:       "RHSA",
        RefID:        "RHSA-2017:0837-01",
        RefURL:       "https://access.redhat.com/errata/RHSA-2017:0837",
      },
      models.Reference{
        ID:           0x8cc,
        DefinitionID: 0x1ae,
        Source:       "CVE",
        RefID:        "CVE-2017-5208",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2017-5208",
      },
      models.Reference{
        ID:           0x8cd,
        DefinitionID: 0x1ae,
        Source:       "CVE",
        RefID:        "CVE-2017-5332",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2017-5332",
      },
      models.Reference{
        ID:           0x8ce,
        DefinitionID: 0x1ae,
        Source:       "CVE",
        RefID:        "CVE-2017-5333",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2017-5333",
      },
      models.Reference{
        ID:           0x8cf,
        DefinitionID: 0x1ae,
        Source:       "CVE",
        RefID:        "CVE-2017-6009",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2017-6009",
      },
      models.Reference{
        ID:           0x8d0,
        DefinitionID: 0x1ae,
        Source:       "CVE",
        RefID:        "CVE-2017-6010",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2017-6010",
      },
      models.Reference{
        ID:           0x8d1,
        DefinitionID: 0x1ae,
        Source:       "CVE",
        RefID:        "CVE-2017-6011",
        RefURL:       "https://access.redhat.com/security/cve/CVE-2017-6011",
      },
    },
  },
}

```

</details>

### Usage: Start goval-dictionary as server mode

```bash
$ goval-dictionary server -h
server:
        server
                [-bind=127.0.0.1]
                [-port=8000]
                [-dbpath=$PWD/oval.sqlite3 or connection string]
                [-dbtype=sqlite3|mysql|postgres|redis]
                [-debug]
                [-debug-sql]
                [-quiet]
                [-log-dir=/path/to/log]

  -bind string
        HTTP server bind to IP address (default: loop back interface) (default "127.0.0.1")
  -dbpath string
        /path/to/sqlite3 or SQL connection string (default "$PWD/oval.sqlite3")
  -dbtype string
        Database type to store data in (sqlite3, mysql, postgres or redis supported) (default "sqlite3")
  -debug
        debug mode (default: false)
  -debug-sql
        SQL debug mode (default: false)
  -quiet
        quiet mode (no output)
  -log-dir string
        /path/to/log (default "/var/log/vuls")
  -port string
        HTTP server port number (default: 1324)

```

----

## Data Source

- [RedHat](https://www.redhat.com/security/data/oval/)
- [Debian](https://www.debian.org/security/oval/)
- [Ubuntu](https://people.canonical.com/~ubuntu-security/oval/)
- [SUSE](http://ftp.suse.com/pub/projects/security/oval/)
- [Oracle Linux](https://linux.oracle.com/security/oval/)
- [Alpine-secdb](https://git.alpinelinux.org/cgit/alpine-secdb/)

----

## Authors

kotakanbe ([@kotakanbe](https://twitter.com/kotakanbe)) created goval-dictionary and [these fine people](https://github.com/kotakanbe/goval-dictionary/graphs/contributors) have contributed.

----

## Change Log

Please see [CHANGELOG](https://github.com/kotakanbe/goval-dictionary/blob/master/CHANGELOG.md).

----

## License

Please see [LICENSE](https://github.com/kotakanbe/goval-dictionary/blob/master/LICENSE).
