# Cryptography
This is a univeristy project on applying text-book RSA with some of my own modifications.
## Requirements

```
python >= 3.8
```

## Setup

```bash
pip install -r requirements.txt
python setup.py build_ext --inplace
```

## Usage

```bash
python app.py [optional parameters]
```
- `-h`: help

See `app.py` ArgumentParser for detailed optional parameters.

## Test
Easily test that all features are working via
```bash
python test.py [-v] 
```

- `-v`: verbose

## Credit

AES credit to https://github.com/boppreh/aes

RSA credit to https://github.com/Legrandin/pycryptodome

Functions that were borrowed have credits on top of them.

## License

As of right now, 09-May-2021, this repo is not for public use. It will later be open after project submission.
