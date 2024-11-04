---
layout: page
title: Huntress CTF 24 OSINT
tags: [CTF, Learning, Warmups]
---

# Ran Somewhere
###  NOTE, this challenge uses a non-standard flag format. Enter the human-readable name of the location. 

Open the provided email, spot the hex encoding filenames right away. Download them and also extract the web [link](https://sites.google.com/view/id-10-t/home).

Hex from the file names converts to 

- note.txt
- findityet.jpg
- nearby.jpg

**note.txt** contains hex which converts to:

__Hey There! You should be more careful next time and not leave your computer unlocked and unattended! You never know what might happen. Well in this case, you lost your flash drive. Don't worry, I will keep it safe and sound. Actually you could say it is now 'fortified'. You can come retrieve it, but you got to find it. I left a couple of files that should help.__  
__- Vigil Ante__

The extracted site for **Id10t Solutions** (hope I spelled that correctly...) suggests the person who lost the flash drive is from **Maryland** (given the tiny writing at the bottom of the pages). Had no success with the two jpg files and Reverse Image search. Though on closer inspection of **nearby.jpg** there is part of a plaque or sign with the word "Frederick".

Based on the clue from "Vigil Ante" - Start searching Google for forts/castles in Maryland. While there was a Fort Frederick in the results, this was a red herring. However, Frederick Armoury pops up. Start looking at images in Google for this and spot the full image of the partial plaque identified. Tried _Frederick Ward Park_ first, but the actual flag to submit was:

**`Reckord Armory`**

