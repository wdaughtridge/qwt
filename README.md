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

## QuickWebTransport server over HTTP/3

### I was originally using Cloudflare Quiche library but switched to Amazon s2n impl.
I still need to replace quiche QPACK usage with my own impl, but the rest of the HTTP/3 and WebTransport logic is all implemented here.

*NOTE: this has not been tested in a production setting. Use at your own risk.*
