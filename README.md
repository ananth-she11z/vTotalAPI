# vTotalAPI v2
Author: Ananth Gottimukala (she11z)
GitHub: https://github.com/ananth-she11z
LinkedIn: https://www.linkedin.com/in/ananth-she11z

vTotalAPI is a python package to work with Virustotal API v2. It has been loaded with most of the API calls for Files, Domains, IPs and URLs. Depending on the type of API key the functionalities and options have been precisely loaded into the module. Below list describes the methods which can be utilized using vTotalAPI module -

  - File Report
  - File Scan
  - File Download
  - File Behaviour
  - File Network Traffic
  - File Feed
  - File Cluster
  - File Search
  - URL Report
  - URL Scan
  - URL Feed
  - Domain Report
  - IP Report
  - Get Comments
  - Put Comments

### Installation

vTotalAPI requires [Python3](https://www.python.org/downloads/) to run.

```sh
$ pip install vTotalAPI
```
### Usage

First thing to import the module and create an instance with API key (public/private)
```sh
import vTotalAPI
key = ''
vt = vTotalAPI.VirusTotal(apikey=key)
```

From this point "vt" object can be used with any method as mentioned above in description. The usage details for each method is described below with argument options available -

### FILES
- FileReport
_hash = Hash of the file
sleep = Sleep time for each request/hash if in bulk
allinfo = Gives more information on the file (Note: This feature is only available for Private/Enterprise API key)
```sh
data = vt.FileReport(_hash=string, sleep=int, allinfo=boolean)
```

- FileScan
file = File to be scanned
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.FileScan(file=binary, sleep=int)
```

- FileDownload (Note: This Endpoint is only available for Private/Enterprise API key)
_hash = Hash of the file
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.FileDownload(_hash=string, sleep=int)
```

- FileBehaviour (Note: This Endpoint is only available for Private/Enterprise API key)
_hash = Hash of the file
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.FileBehaviour(_hash=string, sleep=int)
```

- FileNetworkTraffic (Note: This Endpoint is only available for Private/Enterprise API key)
_hash = Hash of the file
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.FileNetworkTraffic(_hash=string, sleep=int)
```

- FileFeed (Note: This Endpoint is only available for Private/Enterprise API key)
package = Indicates a time window to pull reports on all items received during such window. Timestamp less than 24 hours ago, UTC.
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.FileFeed(package=string, sleep=int)
```
Following can be used to pack the data received -

with open('package.tar.bz2', 'wb') as fd:
  for chunk in response.iter_content(chunk_size=65536):
    fd.write(chunk)

- FileCluster (Note: This Endpoint is only available for Private/Enterprise API key)
date = A date for which we want to access the clustering details in YYYY-MM-DD format.
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.FileCluster(date=string, sleep=int)
```

- FileSearch (Note: This Endpoint is only available for Private/Enterprise API key)
query = Search query
sleep = Sleep time for each request/hash if in bulk
offset = The offset value returned by a previous identical query, allows you to paginate over the results
```sh
data = vt.FileSearch(query=string, sleep=int, offset=string)
```
### URL
- URLReport
resource = A URL for which you want to retrieve the most recent report. You may also specify a scan_id (sha256-timestamp as returned by the URL submission API) to access a specific report.
sleep = Sleep time for each request/hash if in bulk
scan = This is an optional parameter that when set to "1" will automatically submit the URL for analysis if no report is found for it in vTotalAPI's database. In this case the result will contain a scan_id field that can be used to query the analysis report later on.
allinfo = Return additional information about the file
```sh
data = vt.URLReport(resource=string, sleep=int, scan=int32, allinfo=boolean)
```

- URLScan
url = The URL that should be scanned
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.URLScan(url=string, sleep=int)
```

- URLFeed (Note: This Endpoint is only available for Private/Enterprise API key)
package = Indicates a time window to pull reports on all items received during such window
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.URLFeed(package=string, sleep=int)
```
### DOMAIN
- DomainReport
domain = A domain name
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.DomainReport(domain=string, sleep=int)
```
### IP
- IPReport
ip = An IP address
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.IPReport(ip=string, sleep=int)
```
### COMMENTS
- GETComments
resource = Either an md5/sha1/sha256 hash of the file or the URL itself you want to retrieve.
before = A datetime token that allows you to iterate over all comments on a specific item whenever it has been commented on more than 25 times.
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.GETComments(resource=string, sleep=int, before=string)
```

- PUTComments
resource = Either an md5/sha1/sha256 hash of the file or the URL itself you want to retrieve.
comment = The comment's text
sleep = Sleep time for each request/hash if in bulk
```sh
data = vt.PUTComments(resource=string, sleep=int, comment=string)
```
### License
----
MIT License

Copyright (c) 2020 she11z

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.



