# Project developed by Ananth Gottimukala aka she11z
# Python module/library for Virustotal API v2.0
import sys, time, json, requests

class VirusTotal:

    def __init__(self, error_codes=None, **kwargs):
        self.apikey = kwargs['apikey']
        self.error_codes = {

        '403': 'Forbidden. You don\'t have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges',
        '400': 'Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values',
        '204': 'Request rate limit exceeded. You are making more requests than allowed. You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC',
    }

    def FileReport(self, sleep=None, allinfo=None, **kwargs):
        try:
            _hash = kwargs['_hash']
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = {'apikey': self.apikey.strip(), 'resource': _hash.strip(), 'allinfo': allinfo}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def FileScan(self, sleep=None, **kwargs):   # verified
        try:
            file = kwargs['file']
            url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            params = {'apikey': self.apikey.strip()}
            files = {'file': (file, open(file, 'rb'))}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.post(url, files=files, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def FileDownload(self, sleep=None, **kwargs):
        try:
            _hash = kwargs['_hash']
            url = 'https://www.virustotal.com/vtapi/v2/file/download'
            params = {'apikey': self.apikey.strip(), 'hash': _hash.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.content
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def FileBehaviour(self, sleep=None, **kwargs):
        try:
            _hash = kwargs['_hash']
            url = 'https://www.virustotal.com/vtapi/v2/file/behaviour'
            params = {'apikey': self.apikey.strip(), 'hash': _hash.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def FileNetworkTraffic(self, sleep=None, **kwargs):
        try:
            _hash = kwargs['_hash']
            url = 'https://www.virustotal.com/vtapi/v2/file/behaviour'
            params = {'apikey': self.apikey.strip(), 'hash': _hash.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def FileFeed(self, sleep=None, **kwargs):
        try:
            package = kwargs['package']
            url = 'https://www.virustotal.com/vtapi/v2/file/feed'
            params = {'apikey': self.apikey.strip(), 'package': package.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params, stream=True, allow_redirects=True)
            if response.status_code == 200:
                return response.iter_content(chunk_size=65536)
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def FileCluster(self, sleep=None, **kwargs):
        try:
            date = kwargs['date']
            url = 'https://www.virustotal.com/vtapi/v2/file/clusters'
            params = {'apikey': self.apikey.strip(), 'date': date.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params, stream=True, allow_redirects=True)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def FileSearch(self, sleep=None, offset=None, **kwargs):
        try:
            query = kwargs['query']
            url = 'https://www.virustotal.com/vtapi/v2/file/search'
            params = {'apikey': self.apikey.strip(), 'query': query.strip(), 'offset': offset.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def URLReport(self, sleep=None, allinfo=None, scan=None, **kwargs):
        try:
            resource = kwargs['resource']
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': self.apikey.strip(), 'resource': resource.strip(), 'allinfo': allinfo, 'scan': scan}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def URLScan(self, sleep=None, **kwargs):
        try:
            url = kwargs['url']
            vturl = 'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': self.apikey.strip(), 'url': url.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(vturl, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def URLFeed(self, sleep=None, **kwargs):
        try:
            package = kwargs['package']
            url = 'https://www.virustotal.com/vtapi/v2/url/feed'
            querystring = {'apikey': self.apikey.strip(), 'package': package.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=querystring.strip())
            if response.status_code == 200:
                return response.content
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def DomainReport(self, sleep=None, **kwargs):
        try:
            domain = kwargs['domain']
            url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params = {'apikey': self.apikey.strip(), 'domain': domain.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def IPReport(self, sleep=None, **kwargs):
        try:
            ip = kwargs['ip']
            url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params = {'apikey': self.apikey.strip(), 'ip': ip.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def GETComments(self, sleep=None, before=None, **kwargs):
        try:
            resource = kwargs['resource']
            url = 'https://www.virustotal.com/vtapi/v2/comments/get'
            querystring = {'apikey': self.apikey.strip(), 'resource': resource.strip(), 'before': before.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.request('GET', url, params=querystring)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)

    def PUTComments(self, sleep=None, **kwargs):
        try:
            resource = kwargs['resource']
            comment = kwargs['comment']
            vturl = 'https://www.virustotal.com/vtapi/v2/comments/put'
            params = {'apikey': self.apikey.strip(), 'resource': resource.strip(), 'comment': comment.strip()}
            if not sleep == None:
                time.sleep(int(sleep))
            response = requests.post(vturl, params=params)
            if response.status_code == 200:
                return response.json()
            else:
                return self.error_codes[str(response.status_code)]
        except KeyError as e:
            return str(e) + ' Key Error. Either the key is spelled wrong or the key itself is not defined or in a wrong format'
        except Exception as e:
            return str(e)



