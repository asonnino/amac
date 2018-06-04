# Algebraic MACs and keyed-verification anonymous credentials.
[![license](https://img.shields.io/badge/license-GPL3-brightgreen.svg)](https://github.com/asonnino/amac/blob/master/LICENSE)
[![Build Status](https://travis-ci.org/asonnino/amac.svg?branch=master)](https://travis-ci.org/asonnino/amac)

This repo provides an implementation of the work *Algebraic MACs and keyed-verification anonymous credentials.* of Chase *et al.* A link to the original paper is available [here](http://www0.cs.ucl.ac.uk/staff/S.Meiklejohn/files/ccs14.pdf).

We also extend this scheme by providing support for threshold issuance; an implementation is available [here](https://github.com/asonnino/threshold-amac).


## Pre-requisites
This implementation is built on top of [petlib](https://github.com/gdanezis/petlib), make sure to follow [these instructions](https://github.com/gdanezis/petlib#pre-requisites) to install all the pre-requisites.


## Install
If you have `pip` installed, you can install **amac** with the following command:
```
$ pip install amac
```
otherwise, you can build it manually as below:
```
$ git clone https://github.com/asonnino/amac
$ cd amac
$ pip install -e .
```


## Test
Tests can be run as follows:
```
$ pytest -v --cov=amac tests/
```
or simply using tox:
```
$ tox
```

## License
[The GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html)
