import re
import json
import utils
import base64
import yt_dlp  # 2023.7.6
import learnyst
import subprocess

from urllib import parse
from learnyst import Learnyst
from javascript import require
from cdm.devices import devices
from cdm.wvdecrypt import WvDecrypt
from base64 import b64decode, b64encode
from yt_dlp.postprocessor import PostProcessor
from utils import scriptsDir, joinPath, realPath, createDir, isExist

# Generate main config file from definition config before starting
configPath = joinPath(scriptsDir, 'config.json')
if not utils.isExist(configPath):
    utils.copyFile(joinPath(scriptsDir, 'config.def'), configPath)

# Some important variables
config = utils.JSO(configPath, 4)
lstJsPath = joinPath(scriptsDir, 'learnyst.js')
Learnyst.lstJs = require(lstJsPath)


# Use License DRM to decrypt AES encrypted MPD
def decryptMPD(data, offset=0):
    mpdData = Learnyst.decryptStream(b64encode(data).decode(), offset)
    return str(mpdData).encode()


# Use License DRM to decrypt AES encrypted stream
def decryptStreamChunk(chunk, offset):
    decChunk = Learnyst.decryptStreamB64(b64encode(chunk).decode(), offset)
    return b64decode(decChunk.encode())


# Fix download URL by appending query params
def fixDownloadUrl(info_dict):
    parsed_url = parse.urlparse(info_dict['url'])
    if '.lds' not in info_dict['url'] and len(parsed_url.query) < 2:
        parsed_url = parse.urlparse(info_dict['manifest_url'])
        info_dict['url'] += f'?{parsed_url.query}'


# Fetch Widevine keys using PSSH
def fetch_widevine_keys(pssh_kid_map, lr_token):
    got_cert = False
    cert_data = None
    pssh_cache = config.get("psshCacheStore")

    # Get Keys for all KIDs of PSSH
    for pssh in pssh_kid_map.keys():
        print(f'[*] PSSH: {pssh}')

        # Need to fetch even if one key missing
        fetch_keys = False
        if pssh in pssh_cache:
            for kid in pssh_cache[pssh].keys():
                if kid not in pssh_kid_map[pssh]:
                    fetch_keys = True
                    break
        else:
            fetch_keys = True

        if fetch_keys:
            # Fetch License Certificate of not Present
            if not got_cert:
                print(f'[=>] Get Widevine Server License')
                wv_req = Learnyst.genDRMRequest(lrToken, "CAQ=", True)
                cert_data = learnyst.getWidevineLicense(wv_req, lr_token)

                wv_res = Learnyst.decryptResponse(cert_data.decode())
                wv_res = json.loads(wv_res)

                if 'rawLicenseResponse' not in wv_res:
                    print("[X] Widevine DRM Certificate Not Found!")
                    exit(0)

                Learnyst.updateDRMState(wv_res['lstLicense'])
                cert_data = wv_res['rawLicenseResponse']
                got_cert = True

            print(f'[=>] Perform Widevine Handshake for Keys')

            wv_decrypt = WvDecrypt(devices.device_samsung_sm_g935f, cert_data)

            challenge = wv_decrypt.get_challenge(pssh)
            challengeb64 = b64encode(challenge).decode()

            wv_req = Learnyst.genDRMRequest(lrToken, challengeb64, True)

            wv_license = learnyst.getWidevineLicense(wv_req, lr_token)

            wv_res = Learnyst.decryptResponse(wv_license.decode())
            wv_res = json.loads(wv_res)

            if 'rawLicenseResponse' not in wv_res:
                print("[X] Widevine DRM License Not Found!")
                exit(0)

            Learnyst.updateDRMState(wv_res['lstLicense'])

            wv_license = wv_res['rawLicenseResponse']
            wv_decrypt.update_license(wv_license)

            # Add keys to the map
            pssh_cache[pssh] = wv_decrypt.get_keys()

            # Flush to new Cache
            config.set("psshCacheStore", pssh_cache)


# Use mp4decrypt to decrypt vod(video on demand) using kid:key
def decrypt_vod_mp4d(kid, key, input_path, output_path):
    # Create mp4decrypt command
    mp4decPath = realPath(joinPath(scriptsDir, config.get('mp4decPath')))
    command = [mp4decPath, '--key', f"{kid}:{key}", input_path, output_path]
    process = subprocess.Popen(command, stderr=subprocess.PIPE, universal_newlines=True)
    for line in process.stderr:
        print(line)
    process.communicate()


# Use ffmpeg to merge video and audio
def merge_vod_ffmpeg(in_video, in_audio, output_path):
    # Create ffmpeg command
    ffmpegPath = realPath(joinPath(scriptsDir, config.get('ffmpegPath')))
    command = [ffmpegPath, '-hide_banner', '-i', in_video, '-i', in_audio, '-c:v', 'copy', '-c:a', 'copy', output_path]
    process = subprocess.Popen(command, stderr=subprocess.PIPE, universal_newlines=True)
    for line in process.stderr:
        print(line)
    process.communicate()


# Use yt-dlp to download vod(video on demand) streams into a video file
def download_vod_ytdlp(url, rid_map):
    print('[=>] Downloading Lesson Video')

    output_dir = config.get('downloadPath')
    output_dir = realPath(joinPath(scriptsDir, output_dir, Learnyst.courseName, Learnyst.courseSection,
                                   Learnyst.courseTitle))
    temp_dir = realPath(joinPath(scriptsDir, config.get('tempPath')))
    ffmpegPath = realPath(joinPath(scriptsDir, config.get('ffmpegPath')))

    ydl_opts = {
        'no_warnings': True,
        'format': 'bv+ba/b',
        'paths': {
            'home': output_dir,
            'temp': temp_dir
        },
        'outtmpl': {
            'default': f'{Learnyst.courseSrcName}.%(ext)s',
        },
        'ffmpeg_location': ffmpegPath,
        'allow_unplayable_formats': True
    }

    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        class DRMDecryptPP(PostProcessor):
            def run(self, info):
                # If hls stream
                if 'requested_formats' not in info:
                    return [], info

                # If decrypted file already there
                if 'filepath' not in info['requested_formats'][0]:
                    return [], info

                del_paths = []
                dec_paths = []
                self.to_screen('Doing Post Processing')
                pssh_cache = config.get("psshCacheStore")

                for fmts in info['requested_formats']:
                    fmt_id = fmts['format_id']
                    filepath = fmts['filepath']

                    fmt_code = f"f{fmt_id}"
                    outPath = fmts['filepath'].replace(fmt_code, fmt_code + "dec")

                    if fmt_id in rid_map:
                        _data = rid_map[fmt_id]
                        pssh = _data['pssh']
                        kid = _data['kid']

                        if pssh in pssh_cache:
                            _data = pssh_cache[pssh]

                            self.to_screen('Decrypting Widevine DRM')
                            self.to_screen(f'{kid}:{_data[kid]}')
                            decrypt_vod_mp4d(kid, _data[kid], filepath, outPath)

                            del_paths.append(filepath)
                            dec_paths.append(outPath)

                # Merge both decrypted parts
                self.to_screen('Merging Audio and Video')
                merge_vod_ffmpeg(dec_paths[0], dec_paths[1], info['filepath'])

                # Delete temp files
                del_paths.extend(dec_paths)

                # Move final Video to Out Dir
                info['__files_to_move'] = {
                    info['filepath']: None
                }

                self.to_screen('Completed Post Processing')
                return del_paths, info

        ydl.add_post_processor(DRMDecryptPP(), when='post_process')
        ydl.download([url])


# Download lesson attachment files
def download_attachments(attach_name, attach_content_path):
    output_dir = config.get('downloadPath')
    output_path = realPath(joinPath(scriptsDir, output_dir, Learnyst.courseName, Learnyst.courseSection,
                                    Learnyst.courseTitle, attach_name))

    if not isExist(output_path):
        print(f'[=>] Downloading {attach_name}')

        attachment_data = learnyst.getAttachmentPDF(attach_content_path, attach_name)

        if not attachment_data:
            print(f"[X] {attach_name} Attachment Download Failed!")
            exit(0)

        with open(output_path, "wb") as pdf_file:
            pdf_file.write(attachment_data)


# Download lesson encrypted pdf
def download_enc_pdf(url):
    print('[=>] Downloading Lesson PDF')

    output_dir = config.get('downloadPath')
    output_dir = realPath(joinPath(scriptsDir, output_dir, Learnyst.courseName, Learnyst.courseSection,
                                   Learnyst.courseTitle))
    output_path = f"{output_dir}/{Learnyst.courseSrcName}"

    createDir(output_dir)  # Create directory path for storage

    if not isExist(output_path):
        pdf_enc_data = learnyst.getLessonPDF(url)

        if not pdf_enc_data:
            print("[X] PDF Download Failed!")
            exit(0)

        print('[=>] Decrypting Lesson PDF')
        pdf_dec_data = decryptStreamChunk(pdf_enc_data, 0)

        with open(output_path, "wb") as pdf_file:
            pdf_file.write(pdf_dec_data)

        print("[=>] PDF Downloaded Successfully!")
    else:
        print("[=>] PDF Already Download!")


if __name__ == '__main__':
    print('[=>] Learnyst Downloader Starting')

    if not config.get("lrToken"):
        print("[!] User Token is Missing, Please put valid token in config.json")
        exit(0)

    lrToken = config.get("lrToken") 
    if not learnyst.checkTokenValidity(lrToken):
        print("[X] User Token Expired!")
        exit(0)

    # Use token to get some data
    token_data = base64.b64decode(lrToken.split('.')[1].strip() + "=")
    userData = json.loads(token_data)

    Learnyst.schoolId = userData['sid']
    Learnyst.studentId = userData['uid']

    content_url = input(f'[?] Enter Content Url: ')
    if len(content_url) < 1:
        print("[!] Enter Valid Url")
        exit(0)

    # Ref: https://stackoverflow.com/questions/7160737/python-how-to-validate-a-url-in-python-malformed-or-not
    # URL Sanitization
    urlRegex = re.compile(
        r'^(?:http|ftp)s?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    # URL Check
    if re.match(urlRegex, content_url) is None:
        print("Please Provide Valid URL!")
        exit(0)

    # Get and validate section and lesson id
    if content_url[-1] == '?':
        content_url = content_url[:-1]
    content_url = content_url.split('/')
    try:
        int(content_url[-1])
        Learnyst.lessonId = int(content_url[-1])
        Learnyst.courseName = content_url[5]
    except:
        print("Please Provide Valid URL!!")
        exit(0)

    Learnyst.courseId = learnyst.getCourseId(Learnyst.schoolId, Learnyst.courseName)
    if not Learnyst.courseId:
        print("[X] Course Id Not Found!")
        exit(0)

    courseData = learnyst.getCourseDetails(Learnyst.courseId, Learnyst.schoolId, lrToken)
    if not Learnyst.courseId:
        print("[X] Course Details Not Found!")
        exit(0)

    if 'lessons' not in courseData:
        print("[X] Lessons Not Found in Course!")
        exit(0)

    # Trying to find lesson
    lessonData = None
    for lesson in courseData['lessons']:
        if lesson['id'] == Learnyst.lessonId:
            lessonData = lesson
            break

    if not lessonData:
        print("[X] Lesson Details Not Found!")
        exit(0)

    isPdfLesson = lessonData['lesson_type'] == 6
    if not isPdfLesson and lessonData['lesson_type'] != 1:
        print("[X] Only Video or PDF Lessons are Supported!")
        exit(0)

    if 'lesson_data' not in lessonData:
        print("[X] Lesson Data Not Found!")
        exit(0)

    print('[=>] Found Lesson Details')
    print(f'[*] Id: {lessonData["id"]}')
    print(f'[*] Name: {lessonData["title"]}')
    print(f'[*] Description: {lessonData["short_description"]}')

    # Trying to find section
    for section in courseData['sections']:
        if lessonData['section_id'] == section["id"]:
            Learnyst.courseSection = section['title']

    lesson_data = lessonData['lesson_data']
    lesson_data = json.loads(lesson_data)
    if not lesson_data or len(lesson_data) < 1:
        print("[X] Lesson Data Not Found!")
        exit(0)

    # Updating lesson variables
    lesson_data = lesson_data[0]
    Learnyst.courseName = courseData['title']
    Learnyst.courseTitle = lessonData["title"]
    courseSrcName = lesson_data['src']
    Learnyst.courseSrcName = courseSrcName if isPdfLesson else courseSrcName[:-4]
    Learnyst.contentPathPrefix = lesson_data['content_path']
    contentId = lesson_data['content_id'].split('/')
    if len(contentId) != 2:
        print("[X] Content Id Not Valid!")
        exit(0)
    Learnyst.contentId = contentId[0]
    contentPathExtn = lesson_data['content_path_extn'].split('/')
    if len(contentPathExtn) != 2:
        print("[X] Content Path External Not Valid!")
        exit(0)
    Learnyst.contentPathExtn = contentPathExtn[-1]

    # Learnyst DRM
    print('[=>] LST DRM Handshake Started')
    lstDrmReq = Learnyst.genDRMRequest(lrToken, "", False)

    lstDrmRes = learnyst.getLstLicense(lstDrmReq, lrToken)
    if not lstDrmRes:
        print("[X] LST DRM Handshake Failed!")
        exit(0)

    lstDrmRes = Learnyst.decryptResponse(lstDrmRes.decode())
    lstDrmRes = json.loads(lstDrmRes)

    if 'lstLicense' not in lstDrmRes:
        print("[X] LST DRM License Not Found!")
        exit(0)

    print('[=>] LST DRM Licensed')
    Learnyst.updateDRMState(lstDrmRes['lstLicense'])

    print('[=>] URL Token for Content')
    urlToken = Learnyst.genURLToken()

    print('[=>] Fetching Content URL')
    signedUrl = learnyst.fetchSignedUrl(urlToken, Learnyst.contentPathPrefix, lrToken, isPdfLesson)
    if not signedUrl:
        print("[X] Signed Video Url Not Found!")
        exit(0)

    if isPdfLesson:
        # Fix PDF URL
        signedUrl = signedUrl.replace("*", f"{Learnyst.contentPathExtn}/ldrm/pdfFile_lenc.epdf", 1)

        # Download PDF
        download_enc_pdf(signedUrl)
    else:
        # Fix Video URL
        signedUrl = signedUrl.replace("*", f"{Learnyst.contentPathExtn}/sdrm/ctr/audio_video/stream.lds", 1)

        # Download MPD manifest for PSSH
        print(f'[=>] Getting MPD manifest data')

        mpd_data = learnyst.getMPDData(signedUrl, decryptMPD)
        if not mpd_data:
            print("[!] Failed to get MPD manifest")
            exit(0)

        periods = mpd_data['MPD']['Period']
        if not periods:
            print("[!] Failed to parse MPD manifest")
            exit(0)

        rid_kid, pssh_kid = learnyst.parseMPDData(periods)

        # Proceed for DRM keys only if PSSH is there
        if len(pssh_kid) > 0:
            # Get the Decryption Keys into cache
            fetch_widevine_keys(pssh_kid, lrToken)

            # Download Audio, Video streams
            download_vod_ytdlp(signedUrl, rid_map=rid_kid)

            # Check for PDF attachment
            if 'pdf_file_name' in lessonData and len(lessonData['pdf_file_name']) > 2:
                answer = input('[?] Do you want to download attachments (yes/no)?: ')
                if any(answer.lower() == f for f in ['yes', 'y']):
                    pdf_data = lessonData['pdf_file_name']
                    pdf_data = json.loads(pdf_data)
                    if not pdf_data or len(pdf_data) < 1:
                        print("[X] PDF Data Not Found!")
                        exit(0)

                    # Download PDF Attachment
                    print('[=>] Downloading Lesson Attachments')
                    for data in pdf_data:
                        pdfName = data["src"]
                        pdfContentPath = data['content_path']
                        download_attachments(pdfName, pdfContentPath)
                    print("[=>] Attachments Downloaded Successfully!")
        else:
            print("[!] Can't find PSSH, Content may be Encrypted")
            print("[!] Failed to download content")
            exit(0)

    print("[=>] Learnyst Downloader Complete")
