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
        https://<company>.okta.com/api/v1/logs?since=2021-02-24T00:00:00.000Z&filter=eventType eq "user.session.start"
        """
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
        since = datetime.utcnow() - timedelta(hours=self.time_window)
        url = 'https://{company}.okta.com/api/v1/logs?since={since}&filter=eventType eq "user.session.start"'.format(
            company=self.company,
            since=datetime.strftime(since, "%Y-%m-%dT%H:%M:%S.000Z")
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
        try:
            r.raise_for_status()
        except:
            logger.debug('%s - exception in request: %s %s', 
                self.name, r.status_code, r.content)
            raise
            
        return json.loads(response.content)

    def _process_item(self, item):
        indicator = item['client']['ipAddress']
        value = {
            'type': 'IP',
            'confidence': 100
        }
        return [[indicator, value]]