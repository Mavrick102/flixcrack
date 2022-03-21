import requests
import asyncio
import base64
import json
import time
import os
import re

from .protos import wv_proto2_pb2 as wvproto
from .types import Device, CDMSession, EncryptionKey
from .muxer import Muxer
from .parser import Parse

from Cryptodome.Random import random
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import CMAC, SHA256, HMAC, SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Util import Padding
from datetime import datetime

from .utils import (
    read_data,
    get_profiles,
    shakti_headers,
    metadata_endpoint,
    supported_video_profiles,
    supported_audio_profiles,
    manifests_url,
    licenses_url,
    android_esn
)

from .errors import (
    Denied,
    GeoError,
    LoginError,
    DecryptionError,
    InvalidProfile,
    MSLClientError,
    NetflixStatusError
)

class NetflixClient:
    def __init__(
        self,
        email: str,
        password: str,
        device: str,
        cookies_file: str="cookies.txt",
        download_path: str="downloads",
        audio_profile: str="aac",
        video_profile: str="main",
        quality: int=1080,
        language: str="en-US",
        audio_language: list = ["English"],
        audio_description_language: list = [],
        subtitle_language: list = [],
        forced_language: list = [],
        shaka_executable: str = "shakapackager",
        verbose: bool = False,
        quiet: bool = False
    ):
        if video_profile.lower() not in supported_video_profiles:
            raise InvalidProfile(f"Invalid video profile: {video_profile}")
        if audio_profile.lower() not in map(lambda x: x.lower(),
                supported_audio_profiles.keys()):
            raise InvalidProfile(f"Invalid audio profile: {audio_profile}")
        self.email: str = email
        self.password: str = password
        self.device: Device = Device(device)
        self.audio_profile: str = audio_profile
        self.video_profile: str = video_profile
        self.download_path: str = download_path
        self.quality: int = quality
        self.audio_language: list = audio_language
        self.audio_description_language: list = audio_description_language
        self.subtitle_language: list = subtitle_language
        self.forced_language: list = forced_language
        self.manifest_language: str = language
        self.metadata_langage: str = language.split("-")[0]
        self.cookies: dict = read_data(cookies_file)
        self.verbose: bool = verbose
        self.quiet: bool = quiet
        self.shaka_executable: str = shaka_executable
        self.msl: MSLClient = MSLClient(self)

    def log(self, *args):
        if not self.quiet:
            print(*args)

    def _verbose(self, *args):
        if self.verbose:
            print(*args)

    def get_metadata(self, netflix_id) -> dict:
        build_id = self.cookies["build_id"]
        r = requests.get(
            metadata_endpoint.format(build_id),
            headers=shakti_headers(build_id),
            cookies=self.cookies,
            params = {
                "movieid": str(netflix_id),
                "drmSystem": "widevine",
                "isWatchlistEnabled": "false",
                "isShortformEnabled": "false",
                "isVolatileBillboardsEnabled": "false",
                "languages": self.metadata_langage,
            }
        )
        if r.status_code != 200:
            raise NetflixStatusError("Netflix did not return 200")
        if r.text.strip() == "":
            raise GeoError("Title not available in your country.")
        return r.json()["video"]

    def get_keys(self, media_id) -> list:
        playlist = self.msl.load_playlist(media_id, ignore=["playready-h264hpl40-dash"])    
        drm_header = playlist["result"]["video_tracks"][0]["drmHeader"]["bytes"]
        cert_data_b64 = "CAUSwwUKvQIIAxIQ5US6QAvBDzfTtjb4tU/7QxiH8c+TBSKOAjCCAQoCggEBAObzvlu2hZRsapAPx4Aa4GUZj4/GjxgXUtBH4THSkM40x63wQeyVxlEEo1D/T1FkVM/S+tiKbJiIGaT0Yb5LTAHcJEhODB40TXlwPfcxBjJLfOkF3jP6wIlqbb6OPVkDi6KMTZ3EYL6BEFGfD1ag/LDsPxG6EZIn3k4S3ODcej6YSzG4TnGD0szj5m6uj/2azPZsWAlSNBRUejmP6Tiota7g5u6AWZz0MsgCiEvnxRHmTRee+LO6U4dswzF3Odr2XBPD/hIAtp0RX8JlcGazBS0GABMMo2qNfCiSiGdyl2xZJq4fq99LoVfCLNChkn1N2NIYLrStQHa35pgObvhwi7ECAwEAAToQdGVzdC5uZXRmbGl4LmNvbRKAA4TTLzJbDZaKfozb9vDv5qpW5A/DNL9gbnJJi/AIZB3QOW2veGmKT3xaKNQ4NSvo/EyfVlhc4ujd4QPrFgYztGLNrxeyRF0J8XzGOPsvv9Mc9uLHKfiZQuy21KZYWF7HNedJ4qpAe6gqZ6uq7Se7f2JbelzENX8rsTpppKvkgPRIKLspFwv0EJQLPWD1zjew2PjoGEwJYlKbSbHVcUNygplaGmPkUCBThDh7p/5Lx5ff2d/oPpIlFvhqntmfOfumt4i+ZL3fFaObvkjpQFVAajqmfipY0KAtiUYYJAJSbm2DnrqP7+DmO9hmRMm9uJkXC2MxbmeNtJHAHdbgKsqjLHDiqwk1JplFMoC9KNMp2pUNdX9TkcrtJoEDqIn3zX9p+itdt3a9mVFc7/ZL4xpraYdQvOwP5LmXj9galK3s+eQJ7bkX6cCi+2X+iBmCMx4R0XJ3/1gxiM5LiStibCnfInub1nNgJDojxFA3jH/IuUcblEf/5Y0s1SzokBnR8V0KbA=="
        wvdecrypt = WVDecrypt(
            init_data_b64=drm_header,
            cert_data_b64=cert_data_b64,
            device=self.device
        )
        challenge = wvdecrypt.get_challenge()
        current_sessionId = str(time.time()).replace(".", "")[0:-2]
        data = self.msl.get_license(challenge, current_sessionId)
        if "licenseResponseBase64" not in data["result"][0]:
            raise Denied("You can't get " + \
                f"{self.video_profile.upper()}{self.quality} " \
                f"with {self.device.name} (maybe you need a higher level CDM?)")
        license_b64 = data["result"][0]["licenseResponseBase64"]
        wvdecrypt.update_license(license_b64)
        keyswvdecrypt = wvdecrypt.start_process()[1]
        return keyswvdecrypt

    def get_viewables(self, any_id, episode=None, season=None) -> list:
        download_list = []
        metadata = self.get_metadata(any_id)
        _type = metadata["type"]
        viewable_data = dict(
            viewable_id=metadata["id"],
            title=metadata["title"],
            season=None,
            episode=None
        )
        if _type == "movie":
            download_list.append(viewable_data)
        elif _type == "show":
            if not season:
                season = 1
            for season_item in metadata["seasons"]:
                if season_item["seq"] != season \
                and season != "all":
                    continue
                for episode_item in season_item["episodes"]:
                    if episode == "all" or episode_item["seq"] == episode:
                        episode_data = viewable_data.copy()
                        episode_data.update(dict(
                            viewable_id=episode_item["id"],
                            season=season_item["seq"],
                            episode=episode_item["seq"]
                        ))
                        download_list.append(episode_data)
        return download_list

    async def download(self, viewable_id, output=None) -> str:
        keys = self.get_keys(viewable_id)
        playlist = Parse(self.msl.load_playlist(viewable_id), self)
        output_folder = f"temp{viewable_id}"
        muxed_filename = f"{self.download_path}/" + \
            (output or f"{viewable_id}.mkv")
        video_stream = playlist.video_streams[0]

        encrypted_filename = "".join([
            f"{output_folder}/",
            f"video[{viewable_id}]",
            f"[{video_stream['h']}p]",
            f"[{self.video_profile.upper()}]"
        ])
        decrypted_filename = encrypted_filename + "[Decrypted].mp4"

        if not os.path.exists(output_folder):
            os.mkdir(output_folder)
        if not os.path.exists(encrypted_filename) and \
        not os.path.exists(decrypted_filename):
            self.log(f"Downloading {encrypted_filename} " + \
                f"({self._pretty_size(video_stream['size'])})...")
            await self._aria2c(
                video_stream["url"],
                encrypted_filename
            )
        if not os.path.exists(decrypted_filename):
            self.log(f"Decrypting {encrypted_filename}...")
            await self._decrypt(
                encrypted_filename,
                decrypted_filename, keys
            )

        for language in list(playlist.audio_streams.keys()) + \
        list(playlist.audio_description_streams.keys()):
            language_track = playlist.audio_streams.get(language,
                playlist.audio_description_streams.get(language))
            if not language_track:
                continue
            audio_stream = language_track[0]
            audio_filename = "".join([
                f"{output_folder}/",
                f"audio[{viewable_id}]",
                f"[{audio_stream['language']}]",
                f"[{audio_stream['language_code']}]",
                f"[{self.audio_profile.upper()}]"
            ])
            if not os.path.exists(audio_filename):
                self.log(f"Downloading {audio_filename} " + \
                    f"({self._pretty_size(audio_stream['size'])})...")
                await self._aria2c(
                    audio_stream["url"],
                    audio_filename
                )
                await self._demux_audio(audio_filename, 
                    f"{audio_filename}.{self.audio_profile.lower()}")
        for language in list(playlist.subtitle_streams.keys()) + \
        list(playlist.forced_streams.keys()):
            language_track = playlist.subtitle_streams.get(language,
                playlist.forced_streams.get(language))
            if not language_track:
                continue
            subtitles = language_track[0]
            subtitles_filename = "".join([
                f"{output_folder}/",
                f"subtitles[{viewable_id}]",
                f"[{subtitles['language']}]",
                f"[{subtitles['language_code']}].ass",
            ])
            if not os.path.exists(subtitles_filename):
                self.log(f"Downloading {subtitles_filename}...")
                await self._get_subtitles(subtitles["url"], subtitles_filename)

        self.log(f"Muxing all tracks...")
        muxer = Muxer(output_folder, muxed_filename)
        file_data = await muxer.run()
        for k, v in file_data.items():
            final_name = muxed_filename.replace(f"${k}$", v)
            if os.path.exists(final_name):
                os.remove(final_name)
            os.rename(muxed_filename, final_name)
        self.log(f"Muxed: {final_name}",
            f"({self._pretty_size(os.path.getsize(final_name))})")
        return final_name

    def _pretty_size(self, size: int) -> str:
        return f"{size/float(1<<20):,.0f}MiB"

    def _file_name(self, title, season, episode, group) -> str:
        watchable_name = re.sub(r"[^a-zA-Z0-9 ]", "", title)
        watchable_name = re.sub(" ", ".", watchable_name)
        filename = f"{watchable_name}."
        if season:
            filename += f"S{str(season).zfill(2)}" + \
                f"E{str(episode).zfill(2)}."
            filename += f"NF.WEBDL.$quality$p-{group}.mkv"
        return filename

    async def _get_subtitles(self, url, output):
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-y", "-i", url, output, 
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        std = await proc.communicate()
        self._verbose(std)
        
    async def _decrypt(self, _input, output, keys: list[str]):
        keys_arg = ",".join([
            f"label={random.randint(1, 100)}:key_id={kid}:key={key}" for kid, key in
            map(lambda x: x.split(":"), keys)
        ])
        proc = await asyncio.create_subprocess_exec(
            self.shaka_executable, f"input={_input},stream=video,output={output}", 
            "--enable_raw_key_decryption", "--keys", keys_arg,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        std = await proc.communicate()
        self._verbose(std)
        error = (std[0].decode()+std[1].decode()) \
            .strip().split("\n")[-1].strip()
        if "finalized" not in error.lower():
            if os.path.exists(output):
                os.remove(output)
            raise DecryptionError(f"Error decrypting: {error}")
        os.remove(_input)

    async def _demux_audio(self, _input, output):
        proc = await asyncio.create_subprocess_exec(
            "ffmpeg", "-y", "-i", _input,
            "-map", "0:a", "-c", "copy", output, 
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        std = await proc.communicate()
        self._verbose(std)
        os.remove(_input)

    async def _ffprobe(self, _input) -> dict:
        proc = await asyncio.create_subprocess_shell(
            f"ffprobe -print_format json -show_format -show_streams \"{_input}\" > \"{_input}.json\"",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        std = await proc.communicate()
        self._verbose(std)
        data = json.load(open(f"{_input}.json", "r"))
        os.remove(f"{_input}.json")
        return data

    async def _aria2c(self, _input, output):
        proc = await asyncio.create_subprocess_exec(
            "aria2c", "-x16", "-j16", "-s16",
            "--auto-file-renaming=false",
            "-o", output, _input,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        std = await proc.communicate()
        self._verbose(std)

class MSLClient:
    def __init__(self, config: NetflixClient):
        self.config = config
        self.cdm = CDM()
        self.session = requests.Session()
        self.manifests = manifests_url
        self.licenses = licenses_url
        self.esn = android_esn
        self.email = config.email
        self.password = config.password
        self.device = config.device
        self.save_rsa_location = "netflix_token.json"
        self.languages = config.manifest_language
        self.profiles = get_profiles(
            config.video_profile,
            config.audio_profile,
            config.quality
        )
        self.messageid = random.randint(0, 2 ** 52)
        self.privatekey = RSA.generate(2048)
        self.session_keys = {}
        self.msl_headers = {
			"sender": self.esn,
			"handshake": True,
			"nonreplayable": 2,
			"capabilities": {"languages": [], "compressionalgos": []},
			"recipient": "Netflix",
			"renewable": True,
			"messageid": self.messageid,
			"timestamp": time.time(),
		}
        if not os.path.exists(self.save_rsa_location):
            return self.session_keys.update(self.generate_handshake())
        master_token = self.load_tokens()
        expires = int(master_token["expiration"])
        expiration_date = datetime.utcfromtimestamp(expires)
        current_date = datetime.utcnow()
        
        difference = (expiration_date - current_date).total_seconds() / 60 / 60
        if difference < 10:
            return self.session_keys.update(self.generate_handshake())
        self.session_keys.update({
            "mastertoken": master_token["mastertoken"],
            "sequence_number": master_token["sequence_number"],
            "encryption_key": master_token["encryption_key"],
            "sign_key": master_token["sign_key"],
        })
    
    def load_tokens(self):
        tokens_data = json.load(open(self.save_rsa_location, "r", encoding="utf-8"))
        
        data = {
            "mastertoken": tokens_data["mastertoken"],
            "sequence_number": tokens_data["sequence_number"],
			"encryption_key": base64.standard_b64decode(tokens_data["encryption_key"]),
			"sign_key": base64.standard_b64decode(tokens_data["sign_key"]),
			"RSA_KEY": tokens_data["RSA_KEY"],
			"expiration": tokens_data["expiration"],
		}
        
        return data
    
    def generate_handshake(self):
        headerdata = self.get_keyrequest()
        request = {
			"entityauthdata": {
				"scheme": "NONE",
				"authdata": {"identity": self.esn}
			},
			"signature": "",
			"headerdata": base64.b64encode(
                json.dumps(headerdata).encode("utf8")
            ).decode("utf8"),
		}
        r = self.session.post(self.manifests, json=request)
        handshake = self.parse_handshake(response=r.json())
        return handshake
        
    def get_keyrequest(self):
        self.cdm_session = self.cdm.open_session(
            None, self.device,
            b"\x0A\x7A\x00\x6C\x38\x2B", True
        )
        wv_request = base64.b64encode(
            self.cdm.get_license_request(self.cdm_session)
        ).decode("utf-8")
        
        self.msl_headers["keyrequestdata"] = [{
			"scheme": "WIDEVINE", 
			"keydata": {"keyrequest": wv_request}
		}]

        return self.msl_headers
    
    def parse_handshake(self, response):
        headerdata = json.loads(
            base64.b64decode(response["headerdata"]).decode("utf8")
        )
        
        keyresponsedata = headerdata["keyresponsedata"]
        mastertoken = headerdata["keyresponsedata"]["mastertoken"]
        sequence_number = json.loads(
            base64.b64decode(mastertoken["tokendata"]).decode("utf8")
		)["sequencenumber"]
        
        keydata = keyresponsedata["keydata"]
        
        encryption_key, sign_key = self.process_wv_keydata(keydata)
        tokens_data = {
			"mastertoken": mastertoken,
			"sequence_number": sequence_number,
			"encryption_key": encryption_key,
			"sign_key": sign_key,
		}
        
        tokens_data_save = tokens_data
        tokens_data_save.update({"RSA_KEY": self.privatekey.export_key().decode()})
        tokens_data_save.update({
            "expiration": json.loads(
                base64.b64decode(
                    json.loads(base64.b64decode(response["headerdata"]))[
                        "keyresponsedata"
                    ]["mastertoken"]["tokendata"]
                )
            )["expiration"]
		})
        self.save_tokens(tokens_data_save)
        return tokens_data
    
    def process_wv_keydata(self, keydata):
        wv_response_b64 = keydata["cdmkeyresponse"]
        encryptionkeyid = base64.standard_b64decode(keydata["encryptionkeyid"])
        hmackeyid = base64.standard_b64decode(keydata["hmackeyid"])
        self.cdm.provide_license(self.cdm_session, wv_response_b64)
        keys = self.cdm.get_keys(self.cdm_session)
        return (
			self.find_wv_key(encryptionkeyid, keys, ["AllowEncrypt", "AllowDecrypt"]),
			self.find_wv_key(hmackeyid, keys, ["AllowSign", "AllowSignatureVerify"]),
		)
    
    def find_wv_key(self, kid, keys, permissions):
        for key in keys:
            if key.kid != kid:
                continue
            if key.type != "OPERATOR_SESSION":
                continue
            if not set(permissions) <= set(key.permissions):
                continue
            return key.key
        return None
    
    def save_tokens(self, tokens_data):
        data = {
            "mastertoken": tokens_data["mastertoken"],
			"sequence_number": tokens_data["sequence_number"],
			"encryption_key": base64.standard_b64encode(
				tokens_data["encryption_key"]
			).decode("utf-8"),
			"sign_key": base64.standard_b64encode(tokens_data["sign_key"]).decode("utf-8"),
			"RSA_KEY": tokens_data["RSA_KEY"],
			"expiration": tokens_data["expiration"],
		}
        
        with open(self.save_rsa_location, "w+", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=4))
            
    def get_license(self, challenge, session_id):
        timestamp = int(time.time() * 10000)
        license_request_data = {
			"version": 2,
			"url": self.license_path,
			"id": timestamp,
			"languages": "en_US",
			"echo": "drmsessionId",	
			"params": [{
                "drmSessionId": session_id,
                "clientTime": int(timestamp / 10000),
                "challengeBase64": base64.b64encode(challenge).decode("utf8"),
                "xid": str(timestamp + 1610),
            }]
		}
        
        request_data = self.msl_request(license_request_data)
        r = self.session.post(self.licenses, data=request_data)
        
        try:
            r.json()
        except ValueError:
            msl_license_data = json.loads(
                json.dumps(self.decrypt_response(r.text))
            )
            if msl_license_data.get("result"):
                return msl_license_data
            if msl_license_data.get("errormsg"):
                raise ValueError(msl_license_data["errormsg"])
            raise ValueError(msl_license_data)
        
    def decrypt_response(self, payload):
        try:
            loeade_payload = json.loads(payload)
            if loeade_payload.get("errordata"):
                return json.loads(
                    base64.b64decode(loeade_payload["errordata"]
                ).decode())
        except:
            payloads = re.split(
				r',"signature":"[0-9A-Za-z/+=]+"}', payload.split("}}")[1]
			)
            payloads = [x + "}" for x in payloads]
            new_payload = payloads[:-1]
            
            chunks = []
            for chunk in new_payload:
                try:
                    payloadchunk = json.loads(chunk)["payload"]
                    encryption_envelope = payloadchunk
                    cipher = AES.new(
						self.session_keys["encryption_key"],
						AES.MODE_CBC,
						base64.b64decode(json.loads(
							base64.b64decode(
                                encryption_envelope).decode("utf8")
						)["iv"])
					)
                    
                    plaintext = cipher.decrypt(
						base64.b64decode(json.loads(
							base64.b64decode(
                                encryption_envelope).decode("utf8")
						)["ciphertext"])
					)
                    
                    plaintext = json.loads(Padding.unpad(plaintext, 16).decode("utf8"))
                    
                    data = plaintext["data"]
                    data = base64.b64decode(data).decode("utf8")
                    chunks.append(data)
                except:
                    continue
                
            decrypted_payload = "".join(chunks)
            return json.loads(decrypted_payload)
                
    def load_playlist(self, viewable_id, ignore=[]):
        profiles = self.profiles.copy()
        for i in ignore:
            if i not in profiles:
                continue
            profiles.remove(i)
        payload = {
			"version": 2,
			"url": "/manifest",
			"id": int(time.time()),
			"languages": self.languages,
			"params": {
				"type": "standard",
				"viewableId": viewable_id,
				"profiles": profiles,
				"flavor": "STANDARD",
				"drmType": "widevine",
				"usePsshBox": True,
				"useHttpsStreams": True,
				"supportsPreReleasePin": True,
				"supportsWatermark": True,	
				"supportsUnequalizedDownloadables": True,
				"requestEligibleABTests": True,											
				"isBranching": False,
				"isNonMember": False,
				"isUIAutoPlay": False,				
				"imageSubtitleHeight": 1080,
				"uiVersion": "shakti-v4bf615c3",
				"uiPlatform": "SHAKTI",
				"clientVersion": "6.0026.291.011",
				"desiredVmaf": "plus_lts",
				"showAllSubDubTracks": True,				
				"preferAssistiveAudio": False,
				"deviceSecurityLevel": "3000",
				"licenseType": "standard",
				"titleSpecificData": {str(viewable_id): {"unletterboxed": True}},				
				"videoOutputInfo": [{
					"type": "DigitalVideoOutputDescriptor",
					"outputType": "unknown",
					"supportedHdcpVersions": ["2.2"],
					"isHdcpEngaged": True,
                }]
			}
		}
        
        request_data = self.msl_request(payload)
        response = self.session.post(self.manifests, data=request_data)
        manifest = json.loads(json.dumps(self.decrypt_response(response.text)))
        if error := manifest.get("errormsg", manifest.get("error")):
            if manifest.get("errorcode") == 7:
                raise LoginError(manifest.get("error", {}).get("display", error))
            raise MSLClientError(manifest.get("error", {}).get("display", error))
        if result := manifest.get("result"):
            self.license_path = result["links"]["license"]["href"]
            return manifest
        
    def msl_request(self, data, is_handshake=False):
        header = self.msl_headers.copy()
        header["handshake"] = is_handshake
        header["userauthdata"] = {
			"scheme": "EMAIL_PASSWORD",
			"authdata": {"email": self.email, "password": self.password}
		}
        
        header_envelope = self.msl_encrypt(self.session_keys, json.dumps(header))
        
        header_signature = HMAC.new(
			self.session_keys["sign_key"], header_envelope, SHA256
		).digest()
        
        encrypted_header = {
			"headerdata": base64.b64encode(header_envelope).decode("utf8"),
			"signature": base64.b64encode(header_signature).decode("utf8"),
			"mastertoken": self.session_keys["mastertoken"],
		}
        
        payload = {
			"messageid": self.messageid,
			"data": base64.b64encode(json.dumps(data).encode()).decode("utf8"),
			"sequencenumber": 1,
			"endofmsg": True,
		}
        
        payload_envelope = self.msl_encrypt(self.session_keys, json.dumps(payload))
        
        payload_signature = HMAC.new(
			self.session_keys["sign_key"], payload_envelope, SHA256
		).digest()
        
        payload_chunk = {
			"payload": base64.b64encode(payload_envelope).decode("utf8"),
			"signature": base64.b64encode(payload_signature).decode("utf8"),
		}
        return json.dumps(encrypted_header) + json.dumps(payload_chunk)
    
    def msl_encrypt(self, msl_session, plaintext):
        cbc_iv = os.urandom(16)
        encryption_envelope = {
			"keyid": "{}_{}".format(
                self.esn, msl_session["sequence_number"]
            ),
			"sha256": "AA==",
			"iv": base64.b64encode(cbc_iv).decode("utf8"),
		}
        plaintext = Padding.pad(plaintext.encode("utf8"), 16)
        cipher = AES.new(msl_session["encryption_key"], AES.MODE_CBC, cbc_iv)
        ciphertext = cipher.encrypt(plaintext)
        encryption_envelope["ciphertext"] = base64.b64encode(ciphertext).decode("utf8")
        return json.dumps(encryption_envelope).encode("utf8")

class CDM:
    def __init__(self):
        self.sessions: dict = {}

    def open_session(
        self,
        init_data_b64,
        device,
        raw_init_data=None,
        offline=False
    ):
        rand_ascii = "".join(random.choice("ABCDEF0123456789") for _ in range(16))
        session_id = (rand_ascii + "0100000000000000").encode("ascii")
        if raw_init_data and isinstance(raw_init_data, (bytes, bytearray)):
            self.raw_pssh, init_data = True, raw_init_data
        else:
            self.raw_pssh, init_data = False, self.parse_init_data(init_data_b64)
        cdm_session = CDMSession(
            session_id,
            init_data,
            device,
            offline
        )
        self.sessions[session_id] = cdm_session
        return session_id

    def parse_init_data(self, init_data_b64):
        cenc_header = wvproto.WidevineCencHeader()
        cenc_header.ParseFromString(base64.b64decode(init_data_b64)[32:])
        return cenc_header

    def close_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]

    def set_service_certificate(self, session_id, cert_b64):
        session = self.sessions[session_id]
        message = wvproto.SignedMessage()
        message.ParseFromString(base64.b64decode(cert_b64))
        service_certificate = wvproto.SignedDeviceCertificate()
        service_certificate.ParseFromString(
            message.Msg if message.Type
            else base64.b64decode(cert_b64)
        )
        session.service_certificate = service_certificate
        session.privacy_mode = True

    def get_license_request(self, session_id):
        session = self.sessions[session_id]
        license_request = wvproto.SignedLicenseRequestRaw() \
            if self.raw_pssh else wvproto.SignedLicenseRequest()
        client_id = wvproto.ClientIdentification()
        with open(session.device.blob, "rb") as f:
            client_id.ParseFromString(f.read())
        if not self.raw_pssh:
            license_request.Type = wvproto.SignedLicenseRequest.MessageType.Value("LICENSE_REQUEST")
            license_request.Msg.ContentId.CencId.Pssh.CopyFrom(session.init_data)
        else:
            license_request.Type = wvproto.SignedLicenseRequestRaw.MessageType.Value("LICENSE_REQUEST")
            license_request.Msg.ContentId.CencId.Pssh = session.init_data
        license_type = wvproto.LicenseType.Value("OFFLINE") \
            if session.offline else wvproto.LicenseType.Value("DEFAULT")
        license_request.Msg.ContentId.CencId.LicenseType = license_type
        license_request.Msg.ContentId.CencId.RequestId = session_id
        license_request.Msg.Type = wvproto.LicenseRequest.RequestType.Value("NEW")
        license_request.Msg.RequestTime = int(time.time())
        license_request.Msg.ProtocolVersion = wvproto.ProtocolVersion.Value("CURRENT")
        license_request.Msg.ClientId.CopyFrom(client_id)

        key = RSA.importKey(open(session.device.private_key).read())
        session.device_key = key
        hash = SHA1.new(license_request.Msg.SerializeToString())
        signature = pss.new(key).sign(hash)
        license_request.Signature = signature
        session.license_request = license_request

        return license_request.SerializeToString()

    def provide_license(self, session_id, license_b64):
        session = self.sessions[session_id]
        license = wvproto.SignedLicense()
        license.ParseFromString(base64.b64decode(license_b64))
        session.license = license
        oaep_cipher = PKCS1_OAEP.new(session.device_key)
        session.session_key = oaep_cipher.decrypt(license.SessionKey)
        lic_req_msg = session.license_request.Msg.SerializeToString()
        enc_key_base = b"ENCRYPTION\000" + lic_req_msg + b"\0\0\0\x80"
        auth_key_base = b"AUTHENTICATION\0" + lic_req_msg + b"\0\0\2\0"
        enc_key = b"\x01" + enc_key_base
        auth_key_1 = b"\x01" + auth_key_base
        auth_key_2 = b"\x02" + auth_key_base
        auth_key_3 = b"\x03" + auth_key_base
        auth_key_4 = b"\x04" + auth_key_base
        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(enc_key)
        enc_cmac_key = cmac_obj.digest()
        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_1)
        auth_cmac_key_1 = cmac_obj.digest()
        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_2)
        auth_cmac_key_2 = cmac_obj.digest()
        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_3)
        auth_cmac_key_3 = cmac_obj.digest()
        cmac_obj = CMAC.new(session.session_key, ciphermod=AES)
        cmac_obj.update(auth_key_4)
        auth_cmac_key_4 = cmac_obj.digest()
        auth_cmac_combined_1 = auth_cmac_key_1 + auth_cmac_key_2
        auth_cmac_combined_2 = auth_cmac_key_3 + auth_cmac_key_4
        session.derived_keys["enc"] = enc_cmac_key
        session.derived_keys["auth_1"] = auth_cmac_combined_1
        session.derived_keys["auth_2"] = auth_cmac_combined_2
        lic_hmac = HMAC.new(session.derived_keys["auth_1"], digestmod=SHA256)
        lic_hmac.update(license.Msg.SerializeToString())
        if lic_hmac.digest() != license.Signature:
            with open("original_lic.bin", "wb") as f:
                f.write(base64.b64decode(license_b64))
            with open("parsed_lic.bin", "wb") as f:
                f.write(license.SerializeToString())
        for key in license.Msg.Key:
            key_id = key.Id or wvproto.License.KeyContainer.KeyType.Name(key.Type).encode("utf-8")
            encrypted_key = key.Key
            iv = key.Iv
            type = wvproto.License.KeyContainer.KeyType.Name(key.Type)
            cipher = AES.new(session.derived_keys["enc"], AES.MODE_CBC, iv=iv)
            decrypted_key = cipher.decrypt(encrypted_key)
            permissions = []
            if type == "OPERATOR_SESSION":
                perms = key._OperatorSessionKeyPermissions
                for (descriptor, value) in perms.ListFields():
                    if value == 1:
                        permissions.append(descriptor.name)
            session.keys.append(
                EncryptionKey(
                    key_id,
                    type,
                    Padding.unpad(decrypted_key, 16),
                    permissions
                )
            )

    def get_keys(self, session_id):
        if session_id in self.sessions:
            return self.sessions[session_id].keys

class WVDecrypt:
    WV_SYSTEM_ID = [
        237, 239, 139, 169,
        121, 214, 74, 206,
        163, 200, 39, 220,
        213, 29, 33, 237
    ]

    def __init__(self, init_data_b64, cert_data_b64, device):
        self.init_data_b64 = init_data_b64
        self.cert_data_b64 = cert_data_b64
        self.device = device
        self.cdm = CDM()

        def check_pssh(pssh_b64):
            pssh = base64.b64decode(pssh_b64)
            if not pssh[12:28] == bytes(self.WV_SYSTEM_ID):
                new_pssh = bytearray([0, 0, 0])
                new_pssh.append(32 + len(pssh))
                new_pssh[4:] = bytearray(b"pssh")
                new_pssh[8:] = [0, 0, 0, 0]
                new_pssh[13:] = self.WV_SYSTEM_ID
                new_pssh[29:] = [0, 0, 0, 0]
                new_pssh[31] = len(pssh)
                new_pssh[32:] = pssh
                return base64.b64encode(new_pssh)
            else:
                return pssh_b64

        self.session = self.cdm.open_session(check_pssh(self.init_data_b64), self.device)
        if self.cert_data_b64:
            self.cdm.set_service_certificate(self.session, self.cert_data_b64)

    def start_process(self):
        keyswvdecrypt = []
        try:
            for key in self.cdm.get_keys(self.session):
                if key.type == "CONTENT":
                    keyswvdecrypt.append("{}:{}".format(key.kid.hex(), key.key.hex()))
        except:
            return False, keyswvdecrypt
        return True, keyswvdecrypt
    
    def get_challenge(self):
        return self.cdm.get_license_request(self.session)

    def update_license(self, license_b64):
        self.cdm.provide_license(self.session, license_b64)
        return True