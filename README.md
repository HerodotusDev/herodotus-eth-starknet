# Starknet-based State Verifier

Herodotus will allow anyone to trustlessly prove any past or current headers, state, and storage values of L1 contracts to other L2 contracts.

## Architecure

Herodotus is built out of the following components:

- L1 messaging contracts
- L2 contract receiving L1 messages
- L2 contract storing and processing L1 block headers
- Facts registry which stores the proven facts

![alt text](https://github.com/marcellobardus/starknet-l2-storage-verifier/blob/master/.github/storage-verifier.png?raw=true)
_Storage Verifier Flow diagram_

## Quick Start
```sh
# Installing pyenv and pyenv-virtualenv.
$> brew install pyenv
$> brew install pyenv-virtualenv

# Install a specific Python version (e.g., 3.7.x).
$> pyenv install 3.7.12

# zsh config (can be replaced with bash etc) for pyenv auto-loading.
$> echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
$> echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
$> echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init --path)"\n  eval "$(pyenv init -)"\nfi' >> ~/.zshrc\n
# Apply changes.
$> source ~/.zshrc

# Creating our venv
$> pyenv virtualenv 3.7.12 herodotus-vn

# Setting locally our Python version.
$> pyenv local 3.7.12

# Loading our newly created env locally.
$> eval "$(pyenv virtualenv-init -)"

# Upgrading pip.
$> pip install --upgrade pip

# Installing tox project manager.
$> pip install tox

# Building the project.
$> tox
```

## Testing

```sh
# Running a specific test.
$> ./.tox/py37/bin/pytest -s -v -vv -x tests/starknet_l1_headers_store.py

# Running all tests.
$> ./.tox/py37/bin/pytest -s -v -vv -x tests/*
```

## Herodotus API

Herodotus has built an API which allows projects to take advantage of Herodotus in a much simpler manner.

Please note: **Herodotus is currently not ready for most production applications**!

This is because the block step limit on Starknet is too low and large requests may fail if they require too many steps. We are in contact with Starkware and are awaiting for them to increase the step limit in the near future, at which time we will complete e2e testing and officially launch Herodotus.

Check out our [API Docs](https://docs.herodotus.dev) to see all of our currently supported endpoints!

If you are interested in building with the Herodotus API, we can give you API access for testing purposes prior to the official launch. Please send any inquiries to: <dev@herodotus.dev>

## Contribute

There are countless usecases for the storage verifier and we are excited to hear what the community wants to build with it! Please reach out to <dev@herodotus.dev> for any partnership, sponsorship, or other matters.
