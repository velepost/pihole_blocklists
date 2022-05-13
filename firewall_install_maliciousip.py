import easyufw.easyufw as ufw
import os
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def fetch_url(url):

    if not url:
        return

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0'}

    print('[i] Fetching:', url)

    try:
        response = urlopen(Request(url, headers=headers))
    except HTTPError as e:
        print('[E] HTTP Error:', e.code, 'whilst fetching', url)
        return
    except URLError as e:
        print('[E] URL Error:', e.reason, 'whilst fetching', url)
        return

    # Read and decode
    response = response.read().decode('UTF-8').replace('\r\n', '\n')

    # If there is data
    if response:
        # Strip leading and trailing whitespace
        response = '\n'.join(x for x in map(str.strip, response.splitlines()))

    # Return the hosts
    return response


regexps_remote = set()
path_maliciousIp = '/home/velibor/make_mycloudBackup'
path_legacy_regex = os.path.join(path_maliciousIp, 'maliciousip.list')

#url_regexps_remote = 'https://raw.githubusercontent.com/mmotti/pihole-regex/master/regex.list'
url_regexps_remote = 'https://www.myvelecloud.com/cgi-bin/hello.pl?action=maliciousip'
# Fetch the remote regexps
str_regexps_remote = fetch_url(url_regexps_remote)

# If regexps were fetched, remove any comments and add to set
if str_regexps_remote:
	regexps_remote.update(x for x in map(str.strip, str_regexps_remote.splitlines()) if x and x[:1] != '#')
	print(f'[i] {len(regexps_remote)} regexps collected from URL')
	with open(path_legacy_regex, 'w') as fWrite:
		for line in sorted(regexps_remote):
			fWrite.write(f'{line}\n')
			ufw.deny('{line}')
else:
    print('[i] No remote regexps were found.')
    exit(1)



    # Prepare final result
print('[i] Done - Please see your ufw status below\n')
print('{ufw.status()} == END')

