# PNG Punked

Inject arbitrary data into PNGs, without breaking the PNG spec.

For technical details on how this works, and outdated Python 2
code, [read this blogpost](https://www.brian.jp/2021/09/17/hiding-a-payload-in-png-files-with-python/).

[original from 2016](https://blog.brian.jp/python/png/2016/07/07/file-fun-with-pyhon.html)

## How to use

### Listing PNG chunks

```shell
~ ./punk.py list source.png
Chunk IHDR, 13 bytes
Chunk IDAT, 226876 bytes
Chunk IEND, 0 bytes
```

### Injecting data

```shell
~ ./punk.py inject source.png output.png mydata
Chunk IHDR, 13 bytes
Chunk IDAT, 226876 bytes
Chunk IEND, 0 bytes
Injecting puNk chunk 0.007944389275074478 kb
Chunk CRC 43b7dda3
Chunk injected!

~ ./punk.py list output.png
Chunk IHDR, 13 bytes
Chunk IDAT, 226876 bytes
Chunk puNk, 16 bytes
Chunk IEND, 0 bytes
```

### Extracting data

```shell
~ ./punk.py extract output.png mydata.txt
Attempting to extract punked data from output.png
Found a punk chunk worth 16 bytes

~ cat mydata.txt 
Attack at dawn!!% 
```

## Examples?

The `/examples` directory contains three files:

* `hide-this`, the content we want to hide
* `source.png`, the image want to use as a source PNG.
* `output.png`, `source.png`, with the new puNk chunk.

You can verify the contents of output.png by running 

```shell
~ ./punk.py list example/output.png 
Chunk IHDR, 13 bytes
Chunk IDAT, 226876 bytes
Chunk puNk, 603 bytes
Chunk IEND, 0 bytes

~ stat --format="%s" example/hide-this 
603
```

## Requirements

* Python 3.9 > 

## Punk chunks in the wild

[New steganography attack targets Azerbaijan](https://blog.malwarebytes.com/threat-analysis/2021/03/new-steganography-attack-targets-azerbaijan/)

[Aurora campaign: Attacking Azerbaijan using multiple RATs](https://blog.malwarebytes.com/threat-intelligence/2021/04/aurora-campaign-attacking-azerbaijan-using-multiple-rats/)

## Tools using punk chunks
[Pixload -- Image Payload Creating tools](https://github.com/chinarulezzz/pixload/)