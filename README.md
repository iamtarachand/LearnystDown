# LearnystDown
 
- LearnystDown is a small Python utility POC to download course content from the Learnyst LMS platform. Similar to my previous project [JCineDown](https://github.com/iamtarachand/JCineDown), I utilize mostly open source stuff to achieve this objective, although this time the challenges were tough as it wasn't straightforward.

- Learnyst were using a server-key synced encryption module within a heavily obfuscated web assembly runtime encrypts and decrypts important requests and responses. To simulate their flow, I had to reuse their module to export a set of functions.(Now they have switched to a custom web player module which is also heavily obfuscated, handles encrypted streaming data and also show watermark of the user thus more secure then the previous method)

- My main goal for this project was to learn about and understand video streaming technologies, as well as DRM's inner workings and drawbacks. Learnyst did an exceptional job utilizing different DRM technologies on the top of their own security for the video content streaming and AWS Cloudfront for the PDF contents.

- To properly use this project, you need to first put the binaries of ffmpeg and mp4decrypt in the `bin` directory, then put the working device ID blob in the `cdn/devices` for the widevine. Also,  after the first run of the program, a config.json will be generated; in that config.json, you will need to place the jwt auth token from the respected Learnyst site's cookies into the lrToken field, and JSPyBridge is used to call javascript functions to perform decryption of the requests and responses. As javascript is involved, you will also need to install node.js prior to setup. You will need to log in with your account that has access to those videos, and then only your token can access them.

> **As of now this method is patched thus this project not working**

## Credits
- [ffmpeg](https://ffmpeg.org/): Combining VOD Segments
- [yt-dlp](https://github.com/yt-dlp/yt-dlp): Downloading VOD Segments
- [JSPyBridge](https://pypi.org/project/javascript/): Interoperate Node.js with Python
- [pywidevine](https://github.com/devine-dl/pywidevine): Widevine Implementation
- [mp4decrypt](https://www.bento4.com/documentation/mp4decrypt/): Decryption of VOD Segments

### Notes
- This project is purely for the educational purpose
- Please don't use this project for pirating any content online
- This is NOT affiliated or approved by Learnyst or their partners
