# “HeadBook” Example Project (INF226, 2023)

* Flask docs: https://flask.palletsprojects.com/en/3.0.x/
* Flask login docs: https://flask-login.readthedocs.io/en/latest/
* Using "Log in with *social network*": https://python-social-auth.readthedocs.io/en/latest/configuration/flask.html

## To Use

### Set up virtual environment and install dependencies

Use the [`venv`](https://docs.python.org/3/library/venv.html) command to create a virtual environment. E.g., on Unix (see web page for how to use it on Windows and with non-Bourne-like shells):

```sh
cd 226book
python -m venv .venv  # or possibly python3
. .venv/bin/activate  # yes there's a dot at the beginning of the line
pip install -r requirements.txt
```

You can exit the virtual environment with the command `deactivate`.

### Run it

```sh
flask -A headbook:app run --reload
```

# Copyright

* `unknown.png` – from [OpenMoji](https://openmoji.org/about/) ([Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/))
* `favicon.(png|ico)` – from [Game Icons](https://game-icons.net/1x1/skoll/knockout.html) ([CC BY 3.0](http://creativecommons.org/licenses/by/3.0/))
* `uhtml.js` – from [µHTML](https://github.com/WebReflection/uhtml) (Copyright (c) 2020, Andrea Giammarchi, [ISC License](https://opensource.org/license/isc-license-txt/))
* Base code by Anya
