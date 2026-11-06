# CyberChef Desktop

A native desktop "cyber swiss-army knife" for encoding, decoding, hashing, ciphers, and data analysis. It is built with **Python**, **Tkinter**, and **SQLite**, uses only the standard library, and needs no browser or internet connection.

> Inspired by the web-based [CyberChef](https://github.com/gchq/CyberChef) by GCHQ. This is an independent project and is not affiliated with it.

## Features

- **70+ operations** across 8 categories:
  - **Encoding:** Base64, Base32, Base85, Hex, Binary, Decimal, URL, HTML entities, Morse code
  - **Crypto / ciphers:** ROT13 / Caesar (with brute force), Atbash, Vigenere, XOR (with 1-byte brute force), RC4
  - **Hashing:** MD5, SHA-1, SHA-2, SHA-3, BLAKE2, All Hashes, HMAC, CRC32, Adler-32
  - **Compression:** Gzip, Zlib, Bzip2 (compress and decompress)
  - **Text:** upper/lower/swap case, reverse, find/replace, regex extract, sort and unique lines, remove whitespace or null bytes, take bytes
  - **Forensics:** hexdump, strings, file-type detection, extract URLs / IPs / emails / hashes, defang and fang URLs, JWT parsing, Unix timestamp conversion
  - **Analysis:** entropy, byte frequency, data statistics
  - **Data format:** JSON beautify / minify, query string parsing
- **Recipe builder:** double-click an operation to add it, then reorder, disable, or remove steps
- **Live auto-bake:** output updates as you type
- **Hex / text output views**, plus load file and save output
- **Magic:** automatically tries chains of decoders to find readable output
- **SQLite storage:** save and load recipes, and restore any previous session from the bake history

## Requirements

- Python 3.8 or newer
- Tkinter (included with the standard Python installers on Windows and macOS; on some Linux systems install it with `sudo apt install python3-tk`)

No third-party packages are needed.

## How to Run

```bash
git clone https://github.com/tabassumbanugitthub/CyberChef-Desktop.git
cd CyberChef-Desktop
python cyberchef.py
```

You can also open `cyberchef.py` in Spyder or IDLE and press **F5**.

A local database file (`cyberchef_desktop.db`) is created automatically next to the script on first run.

## Example

1. Paste `SGVsbG8gV29ybGQ=` into the input box.
2. Double-click **From Base64** to add it to the recipe.
3. The output shows `Hello World`.

Not sure how some data is encoded? Click **Magic** and the app will try decoder chains for you.

## Screenshots

*Add screenshots of the main window, the recipe builder, and the Magic results here.*

## Project Structure

```
CyberChef-Desktop/
├── cyberchef.py   # Operations registry, recipe engine, SQLite layer, and GUI
├── README.md
├── LICENSE
└── .gitignore
```

## Disclaimer

This tool is intended for learning, CTF challenges, and legitimate analysis. The ciphers included (XOR, RC4, Vigenere, Caesar) are not secure for protecting real data.

## Future Improvements

- Split operations, database, and GUI into separate modules
- More operations (AES, RSA, JWT decode)
- Unit tests for each operation
- Drag-and-drop recipe reordering

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
