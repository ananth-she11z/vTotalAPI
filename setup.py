
from distutils.core import setup
setup(
  name = 'vTotalAPI',
  packages = ['vTotalAPI'],
  version = '11.0',
  license='MIT',
  description = 'Virustotal API v2 python module for automation',
  author = 'Ananth Gottimukala',
  author_email = 'ananth.venk88@gmail.com',
  url = 'https://github.com/ananth-she11z/vTotalAPI',
  download_url = 'https://github.com/ananth-she11z/vTotalAPI/archive/11.0.tar.gz',
  keywords = ['Virustotal', 'APIv2', 'Automation', 'API'],
  install_requires=[

          'requests >= 2.22.0',
      ],
  classifiers=[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.8',
  ],
)
