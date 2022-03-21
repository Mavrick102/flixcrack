import random, os, requests, re

from http.cookiejar import MozillaCookieJar

build_id_pattern = r'"BUILD_IDENTIFIER":"([a-z0-9]+)"'

metadata_endpoint = "https://www.netflix.com/api/shakti/{}/metadata"

manifests_url = "https://www.netflix.com/nq/msl_v1/cadmium/pbo_manifests/^1.0.0/router"
licenses_url = "https://www.netflix.com/nq/msl_v1/cadmium/pbo_licenses/^1.0.0/router"

def random_hex(length: int) -> str:
	return "".join(random.choice("0123456789ABCDEF") for _ in range(length))
manifest_esn = f"NFCDIE-03-{random_hex(30)}"
android_esn = f"NFANDROID1-PRV-P-SAMSUSM-G950F-7169-{random_hex(30)}"

def shakti_headers(build_id):
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "es,ca;q=0.9,en;q=0.8",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "Host": "www.netflix.com",
        "Pragma": "no-cache",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36",
        "X-Netflix.browserName": "Chrome",
        "X-Netflix.browserVersion": "79",
        "X-Netflix.clientType": "akira",
        "X-Netflix.esnPrefix": "NFCDCH-02-",
        "X-Netflix.osFullName": "Windows 10",
        "X-Netflix.osName": "Windows",
        "X-Netflix.osVersion": "10.0",
        "X-Netflix.playerThroughput": "1706",
        "X-Netflix.uiVersion": str(build_id),
    }

def build_headers():
    return {
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
        "Accept-Language": "en,en-US;q=0.9",
    }

def get_build_id(cookies: dict) -> str:
    r = requests.get(
        "https://www.netflix.com/browse",
        headers=build_headers(),
        cookies=cookies
    )
    if r.status_code != 200:
        raise Exception("Netflix didn't return 200")
    match = re.search(build_id_pattern, r.text)
    if not match:
        raise Exception("Invalid cookies. (Missing build_id)")
    return match.group(1)

def read_data(cookies_file):
    if not os.path.exists(cookies_file):
        raise Exception(f"Missing cookie file. ({cookies_file})")
    cj = MozillaCookieJar(cookies_file)
    cj.load()
    cookies = {
        cookie.name: cookie.value
        for cookie in cj
    }
    cookies["build_id"] = get_build_id(cookies)
    if "NetflixId" not in cookies:
        raise Exception("Invalid cookies. (Missing NetflixId)")
    return cookies

supported_video_profiles = ["high", "main", "baseline"]
supported_audio_profiles = {
    "aac": [
        "heaac-5.1-dash",
        "heaac-5.1hq-dash",
        "heaac-2-dash",
        "heaac-2hq-dash",
    ],
    "ac3": [
        "dd-5.1-dash",
        "dd-5.1-elem"
    ],
    "eac3": [
        "ddplus-5.1-dash",
        "ddplus-5.1hq-dash",
        "ddplus-2-dash"
    ],
}

def get_profiles(video_profile: str, audio_profile: str, quality: int):
    profiles = [
		"dfxp-ls-sdh",
		"webvtt-lssdh-ios8",
		"BIF240",
		"BIF320"
	]
    profile_id = video_profile[0].lower()
    if quality >= 1080:
        profiles += [
            f"playready-h264{profile_id}pl40-dash"
        ]
    if quality >= 720:
        profiles += [
            f"playready-h264{profile_id}pl31-dash"
        ]
    if quality >= 480:
        profiles += [
            f"playready-h264{profile_id}pl30-dash",
            f"playready-h264{profile_id}pl22-dash"
        ]
    profiles += supported_audio_profiles.get(audio_profile.lower())
    return profiles