# qwt

```
   ____        _                                                    
  / __ \__  __(_)____                                               
 / / / / / / / / ___/                                               
/ /_/ / /_/ / / /__                                                 
\___\_\__,_/_/\___/                                                 
 _       __     __  ______                                       __ 
| |     / /__  / /_/_  __/________ _____  _________  ____  _____/ /_
| | /| / / _ \/ __ \/ / / ___/ __ `/ __ \/ ___/ __ \/ __ \/ ___/ __/
| |/ |/ /  __/ /_/ / / / /  / /_/ / / / (__  ) /_/ / /_/ / /  / /_  
|__/|__/\___/_.___/_/ /_/   \__,_/_/ /_/____/ .___/\____/_/   \__/  
                                           /_/                      
```

## QuicWebTransport server over HTTP/3

### I was originally using Cloudflare Quiche library but switched to Amazon s2n impl.
I still need to replace quiche QPACK usage with my own impl, but the rest of the HTTP/3 and WebTransport logic is all implemented here.

### This fully works with Chrome v135.0.7049.115 - the `launch_chrome.sh` script will open the application on MacOS with the correct
flags to force QUIC on localhost:4433. (Credits to hyper's h3 repository for the handy script)

*NOTE: this has not been tested in a production setting. Use at your own risk.*
