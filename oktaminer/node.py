import logging
import json
from datetime import datetime
from datetime import timedelta
import requests

from minemeld.ft.basepoller import BasePollerFT

logger = logging.getLogger(__name__)

class Miner(BasePollerFT):
    def configure(self):
        super(Miner, self).configure()
        self.multiple_indicator_types = self.config.get('multiple_indicator_types', False)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.time_window = self.config.get('time_window', 8)
        self.verify_cert = self.config.get('verify_cert', True)

        self.company = self.config.get('company', None)
        if self.company is None:
            raise ValueError('%s - API token is required' % (self.company))

        self.api_key = self.config.get('api_key', None)
        if self.api_key is None:
            raise ValueError('%s - API key is required' % (self.api_key))

    def _build_iterator(self, item):
        pass

    def _process_item(self, item):
        pass

class UserMiner(BasePollerFT):
    def configure(self):
        """
        Example URI:
            https://<company>.okta.com/api/v1/logs?since=2021-02-24T00:00:00.000Z&filter=eventType eq "user.session.start"

        configurations:
            polling_timeout (int:20): Polling timeout
            time_window (int:7): number of days for time window
            verify_cert (bool:True): Verify the certificate
            query (str: outcome.result eq "SUCCESS" and eventType eq "user.session.start"): Okta query
            limit (int: 1000):  (over the 1000 is not allowed)
            company (None): name of company
            api_key (str): API Key for Okta
        """
        super(UserMiner, self).configure()

        #self.multiple_indicator_types = self.config.get('multiple_indicator_types', False)
        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.time_window = self.config.get('time_window', 7)
        self.verify_cert = self.config.get('verify_cert', True)
        self.query = self.config.get('query', 'outcome.result eq "SUCCESS" and eventType eq "user.session.start"')

        self.limit = self.config.get('limit', 1000)
        if self.limit > 1000:
            raise ValueError("Max of limit is 1000")

        self.company = self.config.get('company', None)
        if self.company is None:
            raise ValueError('%s - API token is required' % (self.company))

        self.api_key = self.config.get('api_key', None)
        if self.api_key is None:
            raise ValueError('%s - API key is required' % (self.api_key))
            

    def _build_iterator(self, item):
        since = datetime.utcnow() - timedelta(days=self.time_window)
        #outcome.result eq "SUCCESS" and eventType eq "user.session.start"
        url = 'https://{company}.okta.com/api/v1/logs?limit={limit}&since={since}&filter={query}'.format(
            company=self.company,
            limit=self.limit,
            since=datetime.strftime(since, "%Y-%m-%dT%H:%M:%S.000Z"),
            query=self.query,
        )
        headers = {
            'Authorization': 'SSWS %s' % (self.api_key),
            'Accept': 'application/json',
            'Content-type': 'application/json',
        }
        response = requests.get(
            url,
            headers=headers,
            verify=self.verify_cert
        )
        results = None
        try:
            response.raise_for_status()
            results = response.json()
            while 'next' in response.headers['link']:
                next_url = response.headers['link'].split(",")[-1].split(";")[0].strip()[1:-1]
                if next_url == url:
                    break
                url = next_url
                response = requests.get(url, headers=headers, verify=self.verify_cert)
                response.raise_for_status()
                results.extend(response.json())
        except:
            logger.debug('%s - exception in request: %s %s', 
                self.name, response.status_code, response.content)
            raise
        return results

    def _process_item(self, item):
        indicator = item['client']['ipAddress']
        value = {
            'type': 'IPv4',
            'confidence': 100
        }
        return [[indicator, value]]