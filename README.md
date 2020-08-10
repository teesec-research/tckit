## What is this?

A set of scripts to tinker with firmware images of (not so recent) Huawei devices.

## Where to get the binaries from?

* [Firmware Finder for Huawei](https://play.google.com/store/apps/details?id=com.teammt.gmanrainy.huaweifirmwarefinder)
* [androidhost.ru](https://androidhost.ru/)

Obtain a zip file, e.g., `VNS-L31C432B160.zip`, and unzip.

## splitupdate

`splitupdate` extracts several images from the `UPDATE.APP` file that you can find within the zip.

## splitteeos

The tOS and some built-in TAs can be found within the `TEEOS.img`.
Use `splitteeos` to obtain these files.

## globaltask2elf

While most of the built-in TAs are regular ELFs, `globaltask` is not.
`globaltask2elf.py` uses some heuristics to generate an ELF header for the `globaltask` binary.

## tos2elf

Same story for the TC kernel.
`tos2elf.py` uses some heuristics to generate an ELF header from the tOS blob.

## globaltask key extraction

With `globaltaskgencode.py` you can extract the private and public key from `globaltask`.
Given a `globaltask` ELF file, `globaltaskgencode.py` generates a C program that you can execute on an AArch32 device/emulator.
