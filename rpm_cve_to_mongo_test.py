import unittest
import requests_mock
import mongomock as mongomock

from rpm_cve_to_mongo import RPMCVE2Mongo

test_xml = """<rpms>
  <rpm rpm="htdig-2:3.1.6-7.el3">
    <erratum released="2007-06-07">RHBA-2007:0026</erratum>
    <cve>CVE-2000-1191</cve>
  </rpm>
  <rpm rpm="kernel-doc-0:2.6.9-55.EL">
    <erratum released="2007-04-28">RHBA-2007:0304</erratum>
    <cve>CVE-2005-2873</cve>
    <cve>CVE-2005-3257</cve>
    <cve>CVE-2006-0557</cve>
    <cve>CVE-2006-1863</cve>
    <cve>CVE-2007-1592</cve>
    <cve>CVE-2007-3379</cve>
  </rpm>
  <rpm rpm="kernel-smp-0:2.6.9-55.EL">
    <erratum released="2007-04-28">RHBA-2007:0304</erratum>
    <cve>CVE-2005-2873</cve>
    <cve>CVE-2005-3257</cve>
    <cve>CVE-2006-0557</cve>
    <cve>CVE-2006-1863</cve>
    <cve>CVE-2007-1592</cve>
    <cve>CVE-2007-3379</cve>
  </rpm>
</rpms>
"""


class RPMCVEToMongoTestCase(unittest.TestCase):

    @mongomock.patch(servers=(('mongodb://localhost', "27017")))
    def test_instance(self):
        rpm_cve_2_mongo = RPMCVE2Mongo(server="mongodb://user:passwd@localhost", dbuser="AAA", dbpasswd="pass")
        self.assertIsInstance(rpm_cve_2_mongo, RPMCVE2Mongo)

    def test_get_list(self):
        rpm_cve_2_mongo = RPMCVE2Mongo(server="mongodb://user:passwd@localhost", dbuser="AAA", dbpasswd="pass")

        with requests_mock.mock() as m:
            expected_data = "datacontents"
            m.get("https://www.redhat.com/security/data/metrics/rpm-to-cve.xml", text=expected_data)

            rpm_cve_2_mongo.download_list()
            self.assertEqual(b'datacontents', rpm_cve_2_mongo.raw_rpm_cve_data)

    @mongomock.patch(servers=(('mongodb://user:passwd@localhost', "27017")))
    def test_upsert_to_mongo(self):
        rpm_cve_2_mongo = RPMCVE2Mongo(server="mongodb://user:passwd@localhost", dbuser="AAA", dbpasswd="pass")

        with requests_mock.mock() as m:
            m.get("https://www.redhat.com/security/data/metrics/rpm-to-cve.xml", text=test_xml)
            rpm_cve_2_mongo.download_list()
            rpm_cve_2_mongo.upsert_to_mongo()
        collection = rpm_cve_2_mongo.db[rpm_cve_2_mongo.dbcollection]

        self.assertEqual(3, collection.count())
        result = collection.find({"@rpm":"kernel-doc-0:2.6.9-55.EL"})
        cve_expected = [ 'CVE-2005-2873',
                         'CVE-2005-3257',
                         'CVE-2006-0557',
                         'CVE-2006-1863',
                         'CVE-2007-1592',
                         'CVE-2007-3379']
        self.assertEqual(cve_expected, result[0]['cve'])
        self.assertEqual("kernel-doc", result[0]['packagedata']['name'])


if __name__ == '__main__':
    unittest.main()
