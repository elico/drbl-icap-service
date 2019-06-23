DRBL cliet ICAP service
==========
An ICAP service which runs queries against dns\http\https rbl services.
I included here the sources, startup scripts and OpenDNS and Symantech settings that can be used free.

Links for public DNS blacklists services
-----
 - [Norton dns blacklists information](https://dns.norton.com/faq.html)
 - [OpenDNS Home Internet Security](https://www.opendns.com/home-internet-security/)
 - [Yandex.DNS Secure home internet](https://dns.yandex.com/advanced/)
 
Example for squid icap service settings(when the service is installed on the squid machine)
-----
```
icap_service service_req reqmod_precache icap://127.0.0.1:11344/drbl bypass=0 on-overload=wait
adaptation_access service_req deny manager
#adaptation_access service_req deny CONNECT
adaptation_access service_req allow all
```

License
-------
Copyright (c) 2016, Eliezer Croitoru
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
