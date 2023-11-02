---
layout: page
title: Huntress CTF 23 OSINT
subtitle: "Difficulty: Medium"
tags: [CTF, Learning, Warmups]
---

# Where Am I?

_Your friend thought using a JPG was a great way to remember how to login to their private server. Can you find the flag?_

Check out the file for hidden metadata using `exiftool`:

![whereami](/assets/img/huntress_ctf23/whereami.png)

Decoding the base64 string under _Image Description_ reveals the flag:

**`flag{b11a3f0ef4bc170ba9409c077355bba2)`**

# Operation Not Found

_This is the chall1 challenge for the "HuntressCTF2023" challenges on https://osint.golf. It's a lot like Geoguesser if you have ever played :)_

On initial review I tried looking for text to lookup online. There was a construction company clearly visible, but I had no luck on guessing with this as they have a wide footprint within the US. Decided to take a screenshot of the building and try multiple image lookup tools:

![opnotfound](/assets/img/huntress_ctf23/opnotfound.png)

Useful sites:
- [Bing](https://www.bing.com/visualsearch)
- [Google](https://www.labnol.org/reverse/)
- [TinEye](https://tineye.com/)
- [Yandex](https://yandex.com/images?)

Get a hit for **Crosland Tower at Georgia Tech ATL** from the Google Lookup. Find its location in Google Maps, then submit the same location in the challenge page for the flag:

**`flag{c46b7183c9810ec4ddb31b2fdc6a914c}`**

# Under The Bridge

_This is the chall2 challenge for the "HuntressCTF2023" challenges on https://osint.golf. It's a lot like Geoguesser if you have ever played :)_

Being from the UK, I was immediately able to at least narrow down the country based on signage as in this image example:

![underbridge](/assets/img/huntress_ctf23/underbridge.png)

Tried looking up storage unit name that can be seen in the background: **shurgard**. Discover they have quite a few sites around London but need to narrow it down further. I spotted a very old sign, and a new version on what I assumed was a rail bridge so searched for _"HC13 railbridge"_ and discover an image from this [site](https://sketchfab.com/3d-models/rick-roll-bridge-baaad0f63a104360a91d28359d298e22) with an interesting name _"Rick Roll Bridge"_... Taking the name and searching for it reveals this is where Rick Astley filmed THAT song. Enter the location in the challenge page for the flag:

**`flag{fdc8cd4cff2c19e0d1022e78481ddf36}`**
