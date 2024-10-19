from setuptools import setup
from codecs import open  # To use a consistent encoding
from os import path

with open('requirements.txt') as f:
	required = f.read().splitlines()

setup(
	name='cyberus-natus-pehunter',
	version='0.0.1',

	description='Multi-Functional Static Analysis Tool for PE Files',
	url='https://github.com/BrsDincer/cyberus-natus-pehunter',

	author='Baris Dincer \ CyberusNatus',
	author_email='baris.dincer@protonmail.com',
	license='GNU',

	# See https://pypi.python.org/pypi?%3Aaction=list_classifiers
	classifiers=[
		'Development Status :: 3 - Production/Stable',
		'Intended Audience :: Developers',
		'Topic :: Software Development :: Build Tools',
		'License :: OSI Approved :: GNU General Public License (GPL)',
		'Programming Language :: Python :: 3.10.0',
		'Programming Language :: Python :: 3.12.7'
	],

	keywords='CYBERUSNatusPEHunter',

	packages=["CYBERUSNatusPEHunter","CYBERUSNatusPEHunter.modules"],
	package_data={
		'CYBERUSNatusPEHunter': [
			'utils/*.py',
			'yara_rules/*.yar',
			'sources/*.json',
			'sources/*.txt'
			], 
	},
	install_requires=required,
	entry_points={
		'console_scripts': [
			'CYBERUSNatusPEHunter=CYBERUSNatusPEHunter.CYBERUSPEHunter.py',
		],
	},
)