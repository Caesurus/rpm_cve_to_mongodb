#!/usr/bin/env python3
import argparse
import os
import re

import pymongo
import requests
import xmltodict as xmltodict
from pymongo import UpdateOne


class RPMCVE2Mongo(object):
    def __init__(self, server="mongodb://172.16.202.44:27017", dbuser=None, dbpasswd=None,
                 dbauthsource='admin', rpm_to_cve_url=None, dbname="RPMINFO", dbcollection="rpm2cve"):

        self.raw_rpm_cve_data = None
        if rpm_to_cve_url:
            self.rpm_to_cve_url = rpm_to_cve_url
        else:
            self.rpm_to_cve_url = 'https://www.redhat.com/security/data/metrics/rpm-to-cve.xml'

        self.server = server

        if not dbuser:
            raise RuntimeError("dbuser needs to be set")

        if not dbpasswd:
            raise RuntimeError("dbpasswd needs to be set")

        self.dbuser = dbuser
        self.dbpasswd = dbpasswd
        self.dbauthsource = dbauthsource
        self.dbcollection = dbcollection

        self.client = pymongo.MongoClient(server, username=self.dbuser,
                                          password=self.dbpasswd,
                                          authSource=self.dbauthsource,
                                          authMechanism='SCRAM-SHA-1',
                                          serverSelectionTimeoutMS=5)

        self.db = self.client[dbname]
        self.regex_package = re.compile(r"^(?P<name>.*)-(?P<epoch>\d+):(?P<version>.*)-(?P<release>.*)")

    def create_indexes(self):
        self.db[self.dbcollection].create_index([("@rpm", pymongo.ASCENDING)], background=True)
        self.db[self.dbcollection].create_index([
                                                ("packagedata.name", pymongo.ASCENDING),
                                                ("packagedata.release", pymongo.ASCENDING),
                                                ("packagedata.version", pymongo.ASCENDING)], background=True)

    def download_list(self):
        r = requests.get(self.rpm_to_cve_url)
        if 200 == r.status_code:
            self.raw_rpm_cve_data = r.content

    def upsert_to_mongo(self):
        collection = self.db[self.dbcollection]

        operations = []
        rpms = xmltodict.parse(self.raw_rpm_cve_data)
        for rpm in rpms['rpms']['rpm']:
            m = self.regex_package.match(rpm['@rpm'])
            if m:
                rpm['packagedata'] = m.groupdict()
            tmp = UpdateOne({"@rpm": rpm['@rpm']}, {"$set": rpm}, upsert=True)
            operations.append(tmp)

        if len(operations):
            print("Inserting %d docs" % len(operations))
            result = collection.bulk_write(operations, ordered=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pull rpm to cve list from RedHat and upsert into Mongo')
    parser.add_argument("-v", "--verbose", help="modify output verbosity", action="store_true")
    parser.add_argument("-u", "--user", help="specify user for mongodb", action="store")
    parser.add_argument("-p", "--passwd", help="specify password for mongodb", action="store")
    parser.add_argument("-s", "--server", help="specify server connection string: EG mongodb://serverip:port", action="store")

    args = parser.parse_args()

    if args.user:
        dbuser = args.user
    elif "DBUSER" in os.environ:
        dbuser = os.environ["DBUSER"]
    else:
        raise RuntimeError("Please specify user, either -u <username>, or export DBUSER=username")

    if args.passwd:
        dbpasswd = args.passwd
    elif "DBPASSWD" in os.environ:
        dbpasswd = os.environ["DBPASSWD"]
    else:
        raise RuntimeError("Please specify password, either -p <passwd>, or export DBPASSWD=password")

    if args.server:
        dbserver = args.server
    elif "DBSERVER" in os.environ:
        dbserver = os.environ["DBSERVER"]
    else:
        raise RuntimeError("Please specify server, either -s <server>, or export DBSERVER=\"mongodb://serverip:27017\"")

    rpm_cve_2_mongo = RPMCVE2Mongo(server=dbserver, dbuser=dbuser, dbpasswd=dbpasswd)

    rpm_cve_2_mongo.create_indexes()
    rpm_cve_2_mongo.download_list()
    rpm_cve_2_mongo.upsert_to_mongo()
    print("DONE")
