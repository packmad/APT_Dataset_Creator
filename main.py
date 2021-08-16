#!/usr/bin/env python3

import json
import magic
import os
import re
import subprocess
import sys
import traceback

from datetime import datetime
from io import StringIO
from json import JSONEncoder
from multiprocessing import Pool
from pathlib import Path
from pdfminer.converter import TextConverter
from pdfminer.layout import LAParams
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from os.path import join, basename, dirname, isdir, isfile
from tqdm import tqdm
from typing import List, Set, Optional, Tuple
from zipfile import ZipFile


sha256_regex = re.compile(r'[A-Fa-f0-9]{64}')
sha1_regex = re.compile(r'[A-Fa-f0-9]{40}')
md5_regex = re.compile(r'[A-Fa-f0-9]{32}')

EXE_7Z_PATH = '/usr/bin/7z'; assert isfile(EXE_7Z_PATH)
APT_collections = join(dirname(__file__), 'APT_CyberCriminal_Campagin_Collections')
years = [str(i) for i in range(2006, int(datetime.now().year)+1)]


class LamerEncoder(JSONEncoder):
    def default(self, o):
        return o.__dict__


class PDFreport:
    pdf_path: str
    year: Optional[int]
    sha256_hashes: List[str]
    sha1_hashes: List[str]
    md5_hashes: List[str]

    def __init__(self, pdf_path: str, sha256_set: Set, sha1_set: Set, md5_set: Set):
        self.pdf_path = pdf_path.replace(str(APT_collections), '')

        self.year = None
        for y in years:
            if y in self.pdf_path:
                self.year = int(y)
                break

        # there is probably a smarter way to do it with sound regexps, anyway...
        valid_sha1 = set()
        valid_md5 = set()
        for md5 in md5_set:
            md5_valid = True
            for sha1 in sha1_set:
                sha1_valid = True
                for sha256 in sha256_set:
                    if sha256.startswith(sha1):
                        sha1_valid = False
                    if md5 in sha256:
                        md5_valid = False
                if sha1.startswith(md5):
                    md5_valid = False
                if sha1_valid:
                    valid_sha1.add(sha1)
            if md5_valid:
                valid_md5.add(md5)
        self.sha256_hashes = list(sha256_set)
        self.sha1_hashes = list(valid_sha1)
        self.md5_hashes = list(valid_md5)

    def __str__(self) -> str:
        print(self.sha256_hashes, self.sha1_hashes, self.md5_hashes)
        return f'len( sha256={len(self.sha256_hashes)}, ' \
               f'sha1={len(self.sha1_hashes)}, md5={len(self.md5_hashes)} )'


def uppercase_set(uset: Set[str], toadd: List[str]):
    uset.update(e.upper() for e in toadd)


def get_parent(some_path: str) -> str:
    return str(Path(some_path).parent.absolute())


def get_all_files_matching_magic(start_folder: str, magic_begin: str) -> Set[str]:
    ret = set()
    for root, dirs, files in os.walk(start_folder, topdown=False):
        for name in files:
            file_path = os.path.join(root, name)
            m = magic.from_file(file_path)
            if m.startswith(magic_begin):
                ret.add(file_path)
    return ret


def parse_pdf(pdf_path: str) -> Optional[PDFreport]:
    sha256_set = set()
    sha1_set = set()
    md5_set = set()
    try:
        output_string = StringIO()
        with open(pdf_path, 'rb') as in_file:
            doc = PDFDocument(PDFParser(in_file))
            rsrcmgr = PDFResourceManager()
            device = TextConverter(rsrcmgr, output_string, laparams=LAParams())
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            for page in PDFPage.create_pages(doc):
                interpreter.process_page(page)
        pdf_content: str = output_string.getvalue()
        uppercase_set(sha256_set, re.findall(sha256_regex, pdf_content))
        uppercase_set(sha1_set, re.findall(sha1_regex, pdf_content))
        uppercase_set(md5_set, re.findall(md5_regex, pdf_content))
    except Exception:
        traceback.print_exc()
        return None
    return PDFreport(pdf_path, sha256_set, sha1_set, md5_set)


def extract_zip(zip_path: str):
    zip_folder_path = get_parent(zip_path)

    for passwd in [None, 'infected', 'malware', 'virus']:
        cmd = [EXE_7Z_PATH, 'x', '-aoa', zip_path, f'-o{zip_folder_path}']
        if passwd is not None:
            cmd.insert(3, f'-p{passwd}')
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode(errors='ignore')
            if 'Everything is Ok' in output:
                return
        except subprocess.CalledProcessError as e:
            emsg = e.output.decode(errors='replace') if e.output else e
            if 'Wrong password' not in emsg:
                print(f'[!] {zip_path=}', )


def main(tgt_folder: str, outfile_json: str = None):
    assert isdir(tgt_folder)
    zips = get_all_files_matching_magic(tgt_folder, 'Zip archive')
    len_zips = len(zips)
    print('> Extracting ZIPs...')
    with Pool() as pool:
        tqdm(pool.imap(extract_zip, zips), total=len_zips)

    pdfs = get_all_files_matching_magic(tgt_folder, 'PDF')
    print('> Parsing PDFs...')
    with Pool() as pool:
        reports = list(filter(None, tqdm(pool.imap(parse_pdf, pdfs), total=len(pdfs))))
    if outfile_json is None:
        outfile_json = f"reports_{datetime.today().strftime('%Y-%m-%d')}.json"
    with open(outfile_json, 'w') as outfile:
        json.dump(reports, outfile, cls=LamerEncoder)


def test():
    APT_collections = join(dirname(__file__), 'Test_files')
    extract_zip(join(APT_collections, 'test.zip'))
    test_pdf = join(APT_collections, 'test.pdf')
    print(json.dumps(parse_pdf(test_pdf), cls=LamerEncoder))
    os.remove(test_pdf)


if __name__ == "__main__":
    #test(); sys.exit()
    main(APT_collections)
