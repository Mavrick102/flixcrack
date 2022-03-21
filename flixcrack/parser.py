
import iso639
import re

clean_name = re.compile(
    r"(\s*\[Original\]\s*|\s*-\s*Audio Description)"
)

class Parse:
    def __init__(self, playlist, client):
        self.video_streams = sorted([
            dict(
                bitrate=track["bitrate"],
                url=track["urls"][0]["url"],
                size=track["size"],
                w=track["res_w"],
                h=track["res_h"]
            ) for track in playlist["result"]["video_tracks"][0]["streams"]],
            key=lambda x: x["bitrate"], reverse=True
        )
        self.audio_streams = dict()
        for track in playlist["result"]["audio_tracks"]:
            original = iso639.languages.get(
                alpha2=track["language"].split("-")[0]
            ).name
            language = clean_name.sub("", original)
            if "Audio Description" in track["languageDescription"]:
                continue
            if (language not in client.audio_language) and \
            "all" not in client.audio_language:
                continue
            self.audio_streams[language] = sorted([
                dict(
                    bitrate=stream["bitrate"],
                    url=stream["urls"][0]["url"],
                    size=stream["size"],
                    language=language,
                    language_code=track["language"]
                ) for stream in track["streams"]],
                key=lambda x: x["bitrate"], reverse=True
            )

        self.audio_description_streams = dict()
        for track in playlist["result"]["audio_tracks"]:
            original = iso639.languages.get(
                alpha2=track["language"].split("-")[0]
            ).name
            language = clean_name.sub("", original)
            if "Audio Description" not in track["languageDescription"]:
                continue
            if (language not in client.audio_description_language) and \
            "all" not in client.audio_description_language:
                continue
            self.audio_description_streams[language+"AD"] = sorted([
                dict(
                    bitrate=stream["bitrate"],
                    url=stream["urls"][0]["url"],
                    size=stream["size"],
                    language=f"{language} (Audio Description)",
                    language_code=track["language"]
                ) for stream in track["streams"]],
                key=lambda x: x["bitrate"], reverse=True
            )

        self.subtitle_streams = dict()
        for track in playlist["result"]["timedtexttracks"]:
            if track["languageDescription"] == "Off" or \
            not track["language"] or track["isNoneTrack"] or \
            track["trackType"] == "ASSISTIVE": # I skip ASSISTIVE cuz yes
                continue
            original = original = iso639.languages.get(
                alpha2=track["language"].split("-")[0]
            ).name
            language = clean_name.sub("", original)
            if language not in client.subtitle_language and \
            "all" not in client.subtitle_language:
                continue
            # _type = "dfxp-ls-sdh" if track["rawTrackType"] == \
            #     "closedcaptions" else "webvtt-lssdh-ios8"
            url = list(track["ttDownloadables"]["webvtt-lssdh-ios8"]["downloadUrls"].values())[0]
            self.subtitle_streams[language] = [
                dict(
                    url=url,
                    language=language,
                    language_code=track["language"]
                )
            ]

        self.forced_streams = dict()
        for track in playlist["result"]["timedtexttracks"]:
            if not track["isForcedNarrative"] or \
            not track["language"] or track["isNoneTrack"] or \
            track["trackType"] == "ASSISTIVE": # I skip ASSISTIVE cuz yes:
                continue
            original = iso639.languages.get(
                alpha2=track["language"].split("-")[0]
            ).name
            language = clean_name.sub("", original)
            if language not in client.forced_language and \
            "all" not in client.forced_language:
                continue
            url = list(track["ttDownloadables"]["webvtt-lssdh-ios8"]["downloadUrls"].values())[0]
            self.forced_streams[language+"F"] = [
                dict(
                    url=url,
                    language=f"{language} (Forced)",
                    language_code=track["language"]
                )
            ]
