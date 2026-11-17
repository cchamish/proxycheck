## A note from the maintainer

I think the Wikimedia Foundation has already given us quite a fair amount of support in dealing with temporary accounts that abuse open proxies, server-hosted, commercial VPNs, or some widely shared but dedicated IP addresses to vandalise projects. 

However, the tools and intelligence provided through MaxMind and Spur can only go so far, particularly when dealing with those who deliberately go out of their way to use OPs and VPNs for their less-than-honourable purposes.

Inspired by [IPCheck](https://tools.wmflabs.org/ipcheck/index.php), a tool originally developed by SQL (Thanks!), I felt there was still a case for having another tool in my arsenal, the one that takes a more diversified approach to identifying those IP addresses.

IPCheck has been sitting in my bookmarks since 2019. I never removed it, even though the tool has long since been abandoned and is no longer functional, but it's finally 503. Perhaps that says something about my bookmarking habits, perhaps it says something about how much I missed having a tool like this.

This project is still in its early days, and I should probably confess that its maintainer hasn't exactly poured an overwhelming amount of original genius into it. Much of the underlying approach is a reworking of IPCheck's original ideas - so, once again, a big thank you to SQL!

Most of the APIs currently used are also on their free tiers, so please be gentle with them — and with the project itself. Contributions, suggestions, bug reports, and other forms of help are, of course, more than welcome.

And finally, here's to a Wikimedia universe with no vandals whatsoever.

*Yes, I know. One can dream. And one great show can change the world.*

## Data sources and attribution

This product includes GeoLite2 data created by MaxMind, available from [https://www.maxmind.com](https://www.maxmind.com).

ProxyCheck uses [IP2Location.io](https://www.ip2location.io) IP geolocation web service.

Autonomous system and network intelligence includes data from [Cloudflare Radar](https://radar.cloudflare.com/), licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) for non-commercial use, alongside open routing and mobile carrier records from [PeeringDB](https://www.peeringdb.com/) and [bgp.tools](https://bgp.tools/).

Proxy and threat scoring incorporates intelligence from [GetIPIntel.net](https://getipintel.net/) and [ipdata.co](https://ipdata.co/), together with on-demand open proxy port enrichment from [Shodan InternetDB](https://internetdb.shodan.io/) used strictly for non-commercial anti-abuse investigations.

Tor relay and exit node metadata is sourced from [Tor Project Onionoo](https://metrics.torproject.org/onionoo.html) under [CC0-1.0](https://creativecommons.org/publicdomain/zero/1.0/). Offline blocklist and hijacked prefix checks incorporate [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) for non-commercial use and [stamparm/ipsum](https://github.com/stamparm/ipsum) under [The Unlicense](https://unlicense.org/).

Offline VPN and hosting range classification includes datasets from [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn), [IPLocate](https://www.iplocate.io/), and [ipapi-is ip_to_hosting](https://github.com/ipapi-is/ip_to_hosting), licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).

## Privacy and data minimisation

In accordance with the [Wikimedia Cloud Services Terms of Use](https://wikitech.wikimedia.org/wiki/Wikitech:Cloud_Services_Terms_of_use), access is restricted to authorised Wikimedia functionaries and anti-vandalism patrollers via Wikimedia OAuth. No temporary account names, revision identifiers, or requester query histories are stored in the database, and query strings containing inspected IP addresses are omitted from container access logs. Raw upstream provider payloads are retained only transiently in the short-lived L1 Redis cache, whilst persistent L2 cache entries store only sanitised, normalised summary indicators subject to upstream retention limits.
