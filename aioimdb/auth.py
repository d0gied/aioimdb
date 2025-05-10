# -*- coding: utf-8 -*-
import aiohttp
import tempfile
from datetime import datetime, timezone
from base64 import encodebytes

import diskcache
from dateutil.parser import parse
import boto3
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.credentials import Credentials
from urllib.parse import urlparse, parse_qs

from .constants import APP_KEY, HOST, USER_AGENT, BASE_URI


async def _get_credentials():
    url = f'{BASE_URI}/authentication/credentials/temporary/ios82'
    async with aiohttp.ClientSession() as session:
        async with session.post(
            url,
            json={'appKey': APP_KEY},
            headers={'User-Agent': USER_AGENT}
        ) as res:
            res.raise_for_status()
            data = await res.json(encoding='utf-8')
    return data['resource']


class Auth:
    SOON_EXPIRES_SECONDS = 60
    _CREDS_STORAGE_KEY = 'aioimdb-credentials'

    def __init__(self):
        self._cachedir = tempfile.gettempdir()

    def _get_creds(self):
        with diskcache.Cache(directory=self._cachedir) as cache:
            return cache.get(self._CREDS_STORAGE_KEY)

    def _set_creds(self, creds):
        with diskcache.Cache(directory=self._cachedir) as cache:
            cache[self._CREDS_STORAGE_KEY] = creds
        return creds

    def clear_cached_credentials(self):
        with diskcache.Cache(directory=self._cachedir) as cache:
            cache.delete(self._CREDS_STORAGE_KEY)

    def _creds_soon_expiring(self):
        creds = self._get_creds()
        if not creds:
            return creds, True
        expires_at = parse(creds['expirationTimeStamp'])
        now = datetime.now(timezone.utc)
        if now < expires_at:
            time_diff = (expires_at - now).total_seconds()
            if time_diff < self.SOON_EXPIRES_SECONDS:
                return creds, True
            return creds, False
        else:
            return creds, True

    async def get_auth_headers(self, url_path, method='GET', body=''):
        creds, soon_expires = self._creds_soon_expiring()
        if soon_expires:
            creds = self._set_creds(await _get_credentials())

        # Build credentials object directly
        credentials = Credentials(
            access_key=creds['accessKeyId'],
            secret_key=creds['secretAccessKey'],
            token=creds['sessionToken']
        )

        # Parse URL and query parameters
        parsed_url = urlparse(url_path)
        full_url = f"https://{HOST}{parsed_url.path}"
        if parsed_url.query:
            full_url += f"?{parsed_url.query}"

        # Prepare AWS request
        request = AWSRequest(
            method=method,
            url=full_url,
            data=body,
            headers={'User-Agent': USER_AGENT}
        )

        # Sign the request with SigV4
        SigV4Auth(credentials, "execute-api", "us-east-1").add_auth(request)

        return dict(request.headers)
