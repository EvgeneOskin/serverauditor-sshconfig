# Termius CLI utility

[![Build status](https://travis-ci.org/Crystalnix/termius-cli.svg?branch=master)](https://travis-ci.org/Crystalnix/termius-cli)
[![Code Climate](https://codeclimate.com/github/Crystalnix/termius-cli/badges/gpa.svg)](https://codeclimate.com/github/Crystalnix/termius-cli)
[![Test Coverage](https://codeclimate.com/github/Crystalnix/termius-cli/badges/coverage.svg)](https://codeclimate.com/github/Crystalnix/termius-cli/coverage)

Provides command line interface for cross-platform terminal Termius.

[this project used to be named serverauditor-sshconfig in the past]

## Demo

[![demo](https://asciinema.org/a/9v8xuygkowzau16y3zp19u0ov.png)](https://asciinema.org/a/9v8xuygkowzau16y3zp19u0ov?autoplay=1)

## Installation

For macOS users, there is a [Homebrew](http://brew.sh/) formula. Usage:

```bash
$ brew install termius
```

**Note**: By default, the command above installs Bash and zsh completions.

For Linux users, there is a `bootstrap.sh` script. Usage:

```bash
$ curl -sSL https://raw.githubusercontent.com/Crystalnix/termius-cli/master/bootstrap.sh | bash
```

Termius CLI utility can be installed via [pip](http://www.pip-installer.org/en/latest/index.html):

```bash
pip install -U termius
```
or [easy_install](http://pythonhosted.org/distribute/):

```bash
easy_install -U termius
```

## Usage

Login to termius.com

```bash
termius login
```

Pull data from termius.com

```bash
termius pull
```

Create host
```bash
termius host --address localhost --label myhost
```

Connect to host
```
termius connect myhost
```

Push data to termius.com
```bash
termius push
```

Create hosts from ssh config
```bash
termius sync ssh
```

### `termius` vs `serverauditor`

#### Export
A `serverauditor` user used to enter:

```bash
$ serverauditor export
```

Instead of it, a `termius` user enters:

```bash
$ termius sync ssh  # Not required password, or login
$ termius push  # Send all data to the cloud
```

If a client are not logged in, the next command logs it in:
```bash
$ termius login  # One time
```

#### Import

A `serverauditor` user used to enter:

```bash
$ serverauditor import
```

But at the moment `termius` user cannot import data to the `~/.ssh/config`
(this feature is in the schedule).
Instead of it, a `termius` user enters:

```bash
$ termius pull  # Fetch all data from the cloud
$ termius connect use-your-host-alias  # Replace 'use-your-host-alias' with the host alias in the termius database
```

If a client are not logged in, the next command logs it in:
```bash
$ termius login  # One time
```


## License

Please see [LICENSE](https://github.com/Crystalnix/termius-cli/blob/master/LICENSE).



