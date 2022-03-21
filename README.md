
<h1 align="center">
  <br>
  <a href="https://github.com/stefanodvx/flixcrack"><img src="https://github.com/stefanodvx/flixcrack/blob/main/logo.png?raw=true" alt="FlixCrack" height=100></a>
</h1>

<h4 align="center">Python Netflix API Metadata & Downloader for Windows and Linux</h4>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#dependencies">Dependencies</a> •
  <a href="#how-to-use">How To Use</a>
</p>

<h1 align="center">
  <a href="https://github.com/stefanodvx/flixcrack"><img src="https://github.com/stefanodvx/flixcrack/blob/main/screen.png?raw=true" alt="FlixCrack" height=230></a>
</h1>

## Features
### ❗ KEEP IN MIND THAT THIS LIBRARY IS STILL IN BETA

* Get Metadata (title, year, episodes, seasons...) with Shakti API
* Get medias (videos, audios, audio descriptions, subtitles...)
* Decryt Widevine DRM protected content
* Automatically mux all your tracks
* Nice pre-made format for file names
* Very fast multi-connection downloads

## Dependencies

* <a href="https://ffmpeg.org/">FFmpeg</a>
* <a href="https://github.com/aria2/aria2">aria2</a>
* <a href="https://github.com/shaka-project/shaka-packager">Shaka Packager</a>
* <a href="https://mkvtoolnix.download/">MKVToolNix</a>

## How To Use

Extract your cookies.txt from browser (you can use <a href="https://chrome.google.com/webstore/detail/get-cookiestxt/bgaddhkoddajcdgocldbbfleckgcbcid">Get cookies.txt</a>) and put it in your working folder. Then create a folder named "devices" and put your CDM in. Here's an example code, I'm downloading first episode of a series in 1080p with HIGH profile and AAC audio (English).

You can extract a private L3 CDM very easily from an Android phone using <a href="https://github.com/wvdumper/dumper">this tool</a>.

```python3
from flixcrack import NetflixClient
import asyncio

client = NetflixClient(
    email="", # Insert your email here
    password="", # Insert your password here
    device="", # Insert your CDM folder name here
    quality=1080,
    audio_language=["English"],
    language="it-IT", # Metadata language
    video_profile="high",
    quiet=False
)

async def main():
    items = client.get_viewables(81470938, episode=1)
    for item in items:
        await client.download(item["viewable_id"],
            client._file_name(
                item["title"],
                item["season"],
                item["episode"],
                "dvx"
            )
        )
asyncio.run(main())
```
