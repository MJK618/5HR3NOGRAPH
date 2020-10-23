<h1 align="center">
  <br>
  <a href="https://github.com/5HR3D/5HR3NOGRAPH"><img src="https://github.com/5HR3D/5HR3NOGRAPH/blob/main/Images/Screenshot.png" alt="5HR3NOGRAPH"></a>
  <br>
  5HR3NOGRAPH
  <br>
</h1>

<p align="center">An advanced, powerful and handy steganography tool for the terminal.</p>

<h1>Intro</h1> 

SHR3NOGRAPH (Shre-no-graf) is a program for for encoding information in image and audio files through steganography. Steganography is the art of hiding secret data within an ordinary, non-secret, file or message in order to avoid detection. This tool has all the feature of text steganography, audio steganography, image steganography, video stegaography, but has limitations for the host file types.<br>Note: Steganography and Cryptography have complementary purposes and can be used together so just watch the clock for an update :)
## It can hide
- Text and text file in an image
- Text and text file in an audio 
- Text and text file in a gif
- Image in another image
- Image in an audio 
- Image in a gif
- Gif in a gif
- Gif in an image
- Gif in an audio
- Audio in an audio
- Audio in an image
- Audio in a gif
- This list does not end here :)
<br>Please take into consideration that the supported host formats are: PNG, BMP, WebP, GIF, WAV
Images in a different format are automatically converted to PNG. Different audio formats are not supported at all.
The size of the host file must be bigger than the file being incoded.

## Installation

Clone.
```sh
$ git clone https://github.com/5HR3D/5HR3NOGRAPH.git
```
Change directory.
```sh
$ cd 5HR3NOGRAPH
```
## Usage
#### Simple use
Encode:
```sh
$ python3 main.py <text/file> <host file>
```
Decode:
```sh
$ python3 main.py <encoded file>
```
#### Keeping a password
```sh
$ python3 main.py <text/file> <host file> -p
```
Decode:
```sh
$ python3 main.py <encoded file> -p
```
#### More options
```sh
$ python3 main.py -h
```
### Confused?
Are you confused or unable to understand the arguements
```sh
$ python3 run.py
```
You don't even need to install requirements after running the run.py file because it is going to do everything itself. :)

## Note:
- It is advised to move the host file and the file to encode in the same directory of 5HR3NOGRAPH files.
- Please remember the password, you cannot recover it.
- Do not run the script while sudo
- Please use Python3
### Disclaimer 
This Steganography tool was created for educational and personal purposes only. The creators will not be held responsible for any violations of law caused by any means by anyone. Please use this tool at your own risk.

## Contact
Mail: its5hr3d@gmail.com

### Copyrights 5HR3D























