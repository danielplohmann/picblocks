# PicBlocks

An experimental project using position-independent code hashing over basic blocks for code similarity estimation.

## Usage

Both module files in `./picblocks` are runnable and contain examples of their usage:

* `$ python -m picblocks.blockhasher <target_binary_path>` - produces a `block-report` for a single binary.
* `$ python -m picblocks.blockhashmatcher <block_reports_path>` - creates a new `./db/picblocksdb.json` from the `block-reports` located in `<block_reports_path>`
* `$ python -m blocks.blockhashmatcher <block_reports_path> <target_binary_path>` - matches a binary against data stored in `./db/picblocksdb.json` if it exists, or otherwise creates `./db/picblocksdb.json` from the `block-reports` located in `<block_reports_path>`

## Creating a database

The script `hash_malpedia.py` is an example of how to process a collection of binaries into `./block-reports`, which will then be aggreated into a `./db/picblocksdb.json`.

## Running a service

If a `./db/picblocksdb.json` exists, you can run

`$ python app.py` 

to spawn a local demo server (`https://127.0.0.1:9001`) to query against.


## Version History

* 2021-09-12: v1.0.6 - added submission form fields for bitness and base address to force overrides for those values.
* 2021-08-24: v1.0.5 - improved parsing of bitness from submission filenames.
* 2021-08-20: v1.0.4 - Tweaked result visualization, now showing all unique matches beyond the first 20.
